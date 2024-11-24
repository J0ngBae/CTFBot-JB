import re
import discord
from discord import slash_command
from discord.commands import SlashCommandGroup
from discord.ext import tasks, commands
from datetime import *
from dateutil.parser import parse # pip install python-dateutil
import requests
from colorama import Fore, Style
import sys
sys.path.append("..")
from config_vars import *

# All commands for getting data from ctftime.org (a popular platform for finding CTF events)
KST = timezone(timedelta(hours=9))

def ctfPrint(organizers: str, ctf_format: str, weight: float, link: str) -> str:
    __organizers = "👥 **Organizers** : "
    __organizers += f"{organizers}\n\n"
    __format = f"🚩 **CTF Format** : "
    __format += f"{ctf_format}\n\n"
    __weight = "🎯 **Weight** : "
    __weight += f"{weight}\n\n"
    __description = "📋 **Description** : "
    __description += 'Visit CTF Time ➡️ ' + link

    des = __organizers + __format + __weight + __description

    return des

class CtfTime(commands.Cog):

    def __init__(self, bot):
        self.bot = bot
        self.upcoming_l = []
        self.updateDB.start() # pylint: disable=no-member

    async def cog_command_error(self, ctx, error):
        print(error)
    
    def cog_unload(self):
        self.updateDB.cancel() # pylint: disable=no-member

    @tasks.loop(minutes=30, reconnect=True)
    async def updateDB(self):
        # Every 30 minutes, this will grab the 5 closest upcoming CTFs from ctftime.org and update my db with it.
        # I do this because there is no way to get current ctfs from the api, but by logging all upcoming ctfs [cont.]
        # I can tell by looking at the start and end date if it's currently running or not using unix timestamps.
        now = datetime.utcnow()
        unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())
        headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
                }
        upcoming = 'https://ctftime.org/api/v1/events/'
        limit = '5' # Max amount I can grab the json data for
        response = requests.get(upcoming, headers=headers, params=limit)
        jdata = response.json()
        
        info = []
        for num, i in enumerate(jdata): # Generate list of dicts of upcoming ctfs
            ctf_title = jdata[num]['title'].strip()
            (ctf_start, ctf_end) = (parse(jdata[num]['start'].replace('T', ' ').split('+', 1)[0]), parse(jdata[num]['finish'].replace('T', ' ').split('+', 1)[0]))
            (unix_start, unix_end) = (int(ctf_start.replace(tzinfo=timezone.utc).timestamp()), int(ctf_end.replace(tzinfo=timezone.utc).timestamp()))
            dur_dict = jdata[num]['duration']
            (ctf_hours, ctf_days) = (str(dur_dict['hours']), str(dur_dict['days']))
            ctf_link = jdata[num]['url']
            ctf_image = jdata[num]['logo']
            ctf_format = jdata[num]['format']
            ctf_place = jdata[num]['onsite']
            ctf_organizers = jdata[num]['organizers'][0]['name']
            ctf_weight = jdata[num]['weight']
            ctftime_link = jdata[num]['ctftime_url']
            if ctf_place == False:
              ctf_place = 'Online'
            else:
              ctf_place = 'Onsite'
            
            ctf = {
                'name': ctf_title,
                'start': unix_start,
                'end': unix_end,
                'dur': ctf_days+' days, '+ctf_hours+' hours',
                'url': ctf_link,
                'img': ctf_image,
                'format': ctf_place+ ' / ' +ctf_format,
                'organizers': ctf_organizers,
                'weight': ctf_weight,
                'ctftime': ctftime_link
                 }
            info.append(ctf)
        
        got_ctfs = []
        for ctf in info: # If the document doesn't exist: add it, if it does: update it.
            query = ctf['name']
            ctfs.update({'name': query}, {"$set":ctf}, upsert=True)
            got_ctfs.append(ctf['name'])
        print(Fore.WHITE + f"{datetime.now()}: " + Fore.GREEN + f"Got and updated {got_ctfs}")
        print(Style.RESET_ALL)
        
        
        for ctf in ctfs.find(): # Delete ctfs that are over from the db
            if ctf['end'] < unix_now:
                ctfs.remove({'name': ctf['name']})

    @updateDB.before_loop
    async def before_updateDB(self):
        await self.bot.wait_until_ready()
    
    
    @commands.Cog.listener()
    async def on_ready(self):
        try:
            await self.bot.wait_until_ready()
            self.makeEvent.start()
        except Exception as e:
            print('on_ready: ', e)
    
    @tasks.loop(time=time(hour=6, minute=0, second=0, tzinfo=KST))
    async def makeEvent(self):
        # Make Event Upcoming CTF
        try:
            guild = await self.bot.fetch_guild(guild_id)
            print(guild)
            events = [event.name for event in guild.scheduled_events]
            now = datetime.now()
            unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())

            for ctf in ctfs.find():
                if ctf['name'] not in events and ctf['start'] < unix_now:
                    name = ctf['name']
                    start_time = datetime.fromtimestamp(ctf['start'], KST)
                    end_time = datetime.fromtimestamp(ctf['end'], KST)
                    location = ctf['url']
                    ctf_format = ctf['format']
                    organizers = ctf['organizers']
                    weight = ctf['weight']
                    ctftime_link = ctf['ctftime']

                    description = ctfPrint(organizers, ctf_format, weight, ctftime_link)

                    privacy = discord.ScheduledEventPrivacyLevel.guild_only

                    await guild.create_scheduled_event(name=name, description=description,
                                                start_time=start_time, end_time=end_time,
                                                privacy_level=privacy, location=location)

        except Exception as e:
            print('scheduled: ', e)
    
    ctftime = SlashCommandGroup("ctftime", description="ctftime command", guild_ids=[guild_id,])

    @ctftime.command(description="Show now running CTF")
    async def current(self, ctx):
        # Send discord embeds of the currently running ctfs.
        now = datetime.utcnow()
        unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())
        running = False
        
        await ctx.respond(":recycle: Checking Running CTF...")
        for ctf in ctfs.find():
            if ctf['start'] < unix_now and ctf['end'] > unix_now: # Check if the ctf is running
                running = True
                embed = discord.Embed(title=':red_circle: ' + ctf['name']+' IS LIVE', description=ctf['url'], color=15874645)
                start = datetime.utcfromtimestamp(ctf['start']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                end = datetime.utcfromtimestamp(ctf['end']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                if ctf['img'] != '':
                    embed.set_thumbnail(url=ctf['img'])
                else:
                    embed.set_thumbnail(url="https://pbs.twimg.com/profile_images/2189766987/ctftime-logo-avatar_400x400.png")
                    # CTFtime logo
                    
                embed.add_field(name='Duration', value=ctf['dur'], inline=True)
                embed.add_field(name='Format', value=ctf['format'], inline=True)
                embed.add_field(name='Timeframe', value=start+' -> '+end, inline=True)
                await ctx.respond(embed=embed)
        
        if running == False: # No ctfs were found to be running
            await ctx.respond("No CTFs currently running!\nCheck out `/ctftime countdown`, and `/ctftime upcoming` to see when ctfs will start!")

    @ctftime.command(description="Show you up to 1 ~ 5 upcoming CTF, Default is 3")
    async def upcoming(self, ctx, amount=discord.Option(str, description="amount to show upcoming CTF", required=False)):
        # Send embeds of upcoming ctfs from ctftime.org, using their api.
        if not amount:
            amount = '3'
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
        }
        upcoming_ep = "https://ctftime.org/api/v1/events/"
        default_image = "https://pbs.twimg.com/profile_images/2189766987/ctftime-logo-avatar_400x400.png"
        r = requests.get(upcoming_ep, headers=headers, params=amount)
        # print("made request")

        upcoming_data = r.json()
        # print("HERE")

        for ctf in range(0, int(amount)):
            ctf_title = upcoming_data[ctf]["title"]
            (ctf_start, ctf_end) = (upcoming_data[ctf]["start"].replace("T", " ").split("+", 1)[0] + " UTC", upcoming_data[ctf]["finish"].replace("T", " ").split("+", 1)[0] + " UTC")
            (ctf_start, ctf_end) = (re.sub(":00 ", " ", ctf_start), re.sub(":00 ", " ", ctf_end))
            dur_dict = upcoming_data[ctf]["duration"]
            (ctf_hours, ctf_days) = (str(dur_dict["hours"]), str(dur_dict["days"]))
            ctf_link = upcoming_data[ctf]["url"]
            ctf_image = upcoming_data[ctf]["logo"]
            ctf_format = upcoming_data[ctf]["format"]
            ctf_place = upcoming_data[ctf]["onsite"]
            if ctf_place == False:
                ctf_place = "Online"
            else:
                ctf_place = "Onsite"

            embed = discord.Embed(title=ctf_title, description=ctf_link, color=int("f23a55", 16))
            if ctf_image != '':
                embed.set_thumbnail(url=ctf_image)
            else:
                embed.set_thumbnail(url=default_image)

            embed.add_field(name="Duration", value=((ctf_days + " days, ") + ctf_hours) + " hours", inline=True)
            embed.add_field(name="Format", value=(ctf_place + " ") + ctf_format, inline=True)
            embed.add_field(name="Timeframe", value=(ctf_start + " -> ") + ctf_end, inline=True)
            await ctx.respond(embed=embed)

    
    @ctftime.command(description="Show Leaderboard by year")
    async def top(self, ctx, year=discord.Option(str, description="year", required=False)):
        # Send a message of the ctftime.org leaderboards from a supplied year (defaults to current year).
        
        if not year:
            # Default to current year
            year = str(datetime.today().year)
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
        }
        top_ep = f"https://ctftime.org/api/v1/top/{year}/"
        leaderboards = ""
        r = requests.get(top_ep, headers=headers)
        if r.status_code != 200:
            await ctx.send("Error retrieving data, please report this with `>report \"what happened\"`")
        else:
            try:
                top_data = (r.json())[year]
                for team in range(10):
                    # Leaderboard is always top 10 so we can just assume this for ease of formatting
                    rank = team + 1
                    teamname = top_data[team]['team_name']
                    score = str(round(top_data[team]['points'], 4))

                    if team != 9:
                        # This is literally just for formatting.  I'm sure there's a better way to do it but I couldn't think of one :(
                        # If you know of a better way to do this, do a pull request or msg me and I'll add  your name to the cool list
                        leaderboards += f"\n[{rank}]    {teamname}: {score}"
                    else:
                        leaderboards += f"\n[{rank}]   {teamname}: {score}\n"

                await ctx.send(f":triangular_flag_on_post:  **{year} CTFtime Leaderboards**```ini\n{leaderboards}```")
            except KeyError as e:
                await ctx.respond("Please supply a valid year.")
                # LOG THIS
    @ctftime.command(description="Show left time of now running ctf")
    async def timeleft(self, ctx):
        # 현재 진행 중인 ctf의 남은 시간을 출력
        now = datetime.utcnow()
        unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())
        running = False
        for ctf in ctfs.find():
            if ctf['start'] < unix_now and ctf['end'] > unix_now: # Check if the ctf is running
                running = True
                time = ctf['end'] - unix_now 
                days = time // (24 * 3600)
                time = time % (24 * 3600)
                hours = time // 3600
                time %= 3600
                minutes = time // 60
                time %= 60
                seconds = time
                await ctx.send(f"```ini\n{ctf['name']} ends in: [{days} days], [{hours} hours], [{minutes} minutes], [{seconds} seconds]```\n{ctf['url']}")
        
        if running == False:
            await ctx.respond('No ctfs are running!\nUse `/ctftime upcoming` or `/ctftime countdown` to see upcoming ctfs')

    @ctftime.command(description="Show time before start CTF")
    async def countdown(self, ctx, params=discord.Option(str, description="Index of upcoming CTF", required=False)):
        # Send the specific time that upcoming ctfs have until they start.
        now = datetime.utcnow()
        unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())
        
        if params == None:
            self.upcoming_l = []
            index = ""
            for ctf in ctfs.find():
                if ctf['start'] > unix_now:
                    # if the ctf start time is in the future...
                    self.upcoming_l.append(ctf)
            for i, c in enumerate(self.upcoming_l):
                index += f"\n[{i + 1}] {c['name']}\n"
            
            await ctx.respond(f"Type /ctftime countdown <number> to select.\n```ini\n{index}```")
        else:
            if self.upcoming_l != []:
                x = int(params) - 1     
                start = datetime.utcfromtimestamp(self.upcoming_l[x]['start']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                end = datetime.utcfromtimestamp(self.upcoming_l[x]['end']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                    
                time = self.upcoming_l[x]['start'] - unix_now 
                days = time // (24 * 3600)
                time = time % (24 * 3600)
                hours = time // 3600
                time %= 3600
                minutes = time // 60
                time %= 60
                seconds = time
                
                await ctx.respond(f"```ini\n{self.upcoming_l[x]['name']} starts in: [{days} days], [{hours} hours], [{minutes} minutes], [{seconds} seconds]```\n{self.upcoming_l[x]['url']}")
            else: # TODO: make this a function, too much repeated code here.
                for ctf in ctfs.find():
                    if ctf['start'] > unix_now:
                        self.upcoming_l.append(ctf)
                x = int(params) - 1     
                start = datetime.utcfromtimestamp(self.upcoming_l[x]['start']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                end = datetime.utcfromtimestamp(self.upcoming_l[x]['end']).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'
                    
                time = self.upcoming_l[x]['start'] - unix_now 
                days = time // (24 * 3600)
                time = time % (24 * 3600)
                hours = time // 3600
                time %= 3600
                minutes = time // 60
                time %= 60
                seconds = time
                
                await ctx.respond(f"```ini\n{self.upcoming_l[x]['name']} starts in: [{days} days], [{hours} hours], [{minutes} minutes], [{seconds} seconds]```\n{self.upcoming_l[x]['url']}")

def setup(bot):
    bot.add_cog(CtfTime(bot))
