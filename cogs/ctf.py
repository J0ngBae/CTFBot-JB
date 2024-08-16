import discord
from discord.ext import tasks, commands
from discord import SlashCommandGroup
import string
import json
import requests
import sys
import traceback
sys.path.append("..")
from config_vars import *

# All commands relating to server specific CTF data
# Credentials provided for pulling challenges from the CTFd platform are NOT stored in the database.
    # they are stored in a pinned message in the discord channel.

def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        category = ctx.channel.category
        if teamdb[str(ctx.guild.id)].find_one({'name': str(category)}):
            return True
        else:
            await ctx.respond("You must be in a created ctf channel to use ctf commands!")
            return False
    return commands.check(tocheck)

def strip_string(tostrip, whitelist):
    # A string validator to correspond with a provided whitelist.
    stripped = ''.join([ch for ch in tostrip if ch in whitelist])
    return stripped.strip()

class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class CredentialsNotFound(Exception):
    pass
class NonceNotFound(Exception):
    pass

def getChallenges(url, username, password):
    # Pull challenges from a ctf hosted with the commonly used CTFd platform using provided credentials
    whitelist = set(string.ascii_letters+string.digits+' '+'-'+'!'+'#'+'_'+'['+']'+'('+')'+'?'+'@'+'+'+'<'+'>')
    fingerprint = "Powered by CTFd"
    s = requests.session()
    if url[-1] == "/": url = url[:-1]
    r = s.get(f"{url}/login")
    if fingerprint not in r.text:
        raise InvalidProvider("CTF is not based on CTFd, cannot pull challenges.")
    else:
        # Get the nonce from the login page.
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here, my theory is that it is different versions of CTFd
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login, please >report this along with the ctf url.")
        # Login with the username, password, and nonce
        r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials")
        r_chals = s.get(f"{url}/api/v1/challenges")
        all_challenges = r_chals.json()
        r_solves = s.get(f"{url}/api/v1/teams/me/solves")
        team_solves = r_solves.json()
        if 'success' not in team_solves:
            # ctf is user based.  There is a flag on CTFd for this (userMode), but it is not present in all versions, this way seems to be.
            r_solves = s.get(f"{url}/api/v1/users/me/solves")
            team_solves = r_solves.json()
        
        solves = []
        if team_solves['success'] == True:
            for solve in team_solves['data']:
                cat = solve['challenge']['category']
                challname = solve['challenge']['name']
                solves.append(f"<{cat}> {challname}")
        challenges = {}
        if all_challenges['success'] == True:
            for chal in all_challenges['data']:
                cat = chal['category']
                challname = chal['name']
                name = f"<{cat}> {challname}"
                # print(name)
                # print(strip_string(name, whitelist))
                if name not in solves:
                    challenges.update({strip_string(name, whitelist): 'Unsolved'})
                else:
                    challenges.update({strip_string(name, whitelist): 'Solved'})
        else:
            raise Exception("Error making request")
        # Returns all the new challenges and their corresponding statuses in a dictionary compatible with the structure that would happen with 'normal' useage.
        return challenges

def get_ctf_platform(url: str) -> str:
    fingerprint = ["Powered by CTFd", '<meta name="rctf-config"']
    platform = ""
    res = requests.get(url)
    if fingerprint[0] in res.text:
        platform = "CTFd"
    else:
        platform = "rCTF"
    
    return platform


class CTF(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        
    ctf = SlashCommandGroup("ctf", description="ctf command", guild_ids=[guild_id,])

    def get_upcoming_ctf(ctx: discord.AutocompleteContext):
        ctf_name = ctx.options['ctf_name']

        ctf_list = []
        for ctf in ctfs.find():
            ctf_list.append(ctf["name"])

        return ctf_list
    
    def get_ctf_category(ctx: discord.AutocompleteContext):
        ctf_name = ctx.options['ctf_name']

        guild_table = teamdb[str(ctx.interaction.guild_id)]
        ctf_list = []
        for ctf in guild_table.find():
            ctf_list.append(ctf["name"])
        
        return ctf_list
    
    def get_joined_ctf(ctx: discord.AutocompleteContext):
        ctf_name = ctx.options['ctf_name']

        return [ctx.interaction.channel.category.name]

    def get_credential_type(ctx: discord.AutocompleteContext):
        ctf_platform = ctx.options['ctf_platform']
        ctf_name = ctx.interaction.channel.category.name
        url = ""
        for ctf in ctfs.find():
            if ctf_name == ctf["name"]:
                url = ctf["url"]
                break
        
        platform = get_ctf_platform(url)

        return [platform]


    #### /ctf create ctf_name : Create CTF Category & Channels ####
    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    async def create(self, ctx, ctf_name: discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_upcoming_ctf))): # type: ignore
        # Create a new channel in the CTF category (default='CTF' or configured with the configuration extension)       

        general_channel = "general"
        botcmd_channel = "👻-botcmd"
        account_channel = "🔑-account"
        notice_channel = "📢-notice"
        solved_channel = "🎉-solved"
        scoreboard_channel = "📈-scoreboard"

        category = discord.utils.get(ctx.guild.categories, name=ctf_name)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            # create role & Set Permissions
            role = await ctx.guild.create_role(name=ctf_name, mentionable=True, color=0xC70039)
            ctf_user = discord.utils.get(ctx.guild.roles, name="@everyone")

            # @everyone role can't view ctf channel
            overwrites = {
                role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_messages=True),
                ctf_user: discord.PermissionOverwrite(view_channel=False, send_messages=False, read_messages=False)
            }

            rdonly_overwrite = {
                role: discord.PermissionOverwrite(view_channel=True, send_messages=False, read_messages=True),
                ctf_user: discord.PermissionOverwrite(view_channel=False, send_messages=False, read_messages=False)
            }

            await ctx.guild.create_category(name=ctf_name, overwrites=overwrites)
            await ctx.interaction.response.send_message(f"✅ Created `{ctf_name}` Category.")

            category = discord.utils.get(ctx.guild.categories, name=ctf_name)
        
            await ctx.guild.create_text_channel(name=general_channel, overwrites=overwrites, category=category)
            await ctx.guild.create_text_channel(name=botcmd_channel, overwrites=overwrites, category=category)
            await ctx.guild.create_text_channel(name=account_channel, overwrites=rdonly_overwrite, category=category)
            await ctx.guild.create_text_channel(name=notice_channel, overwrites=rdonly_overwrite, category=category)
            await ctx.guild.create_text_channel(name=solved_channel, overwrites=rdonly_overwrite, category=category)
            await ctx.guild.create_text_channel(name=scoreboard_channel, overwrites=rdonly_overwrite, category=category)

            server = teamdb[str(ctx.guild.id)]

            # teamdb update {"name", "category"}
            ctf_info = {'name': ctf_name, "category": ctf_name}
            server.update({'name': ctf_name}, {"$set": ctf_info}, upsert=True)
            # Give a visual confirmation of completion.
        else:
            await ctx.interaction.response.send_message(f"❌ Already created `{ctf_name}` Category.")

    #### Create CTF Category & Channels End ####
    
    #### /ctf delete ctf_name Delete CTF Info from DB & Disord Category & Channels ####
    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def delete(self, ctx, ctf_name: discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_joined_ctf))): # type: ignore
        # Delete role from server, delete entry from db
        try:
            role = discord.utils.get(ctx.guild.roles, name=str(ctf_name))
            await role.delete()
            await ctx.respond(f"`{role.name}` role deleted")
        except: # role most likely already deleted with archive
            pass
        teamdb[str(ctx.guild.id)].remove({'name': str(ctf_name)})
        await ctx.respond(f"`{str(ctf_name)}` deleted from db")

        # delete channel in category
        category = ctx.channel.category
        for channel in category.channels:
            await channel.delete()
        
        # delete category
        await category.delete()

    #### Delete CTF Info from DB & Disord Category & Channels End ####
    
    # @ctf.command()
    # async def test(self, ctx, ctf_name=discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_ctf_category))):
    #     #user = ctx.guild.members
    #     category = discord.utils.get(ctx.guild.categories, name=ctf_name)

    #     print(category.channels)

    #     await ctx.respond("✅ Work")
    
    #### /ctf archive ctf_name Archiving CTF Info ####
    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def archive(self, ctx, ctf_name: discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_ctf_category))): # type: ignore
        # Delete the role, and move the ctf channel to either the default category (Archive) or whatever has been configured.
        ctf_user = discord.utils.get(ctx.guild.roles, name="@everyone")
        perm_member_rd = {}
        perm_member = {}
        category = discord.utils.get(ctx.guild.categories, name=ctf_name)
        general_channel = category.channels[0]
        members = general_channel.members

        # Can read only joined user
        for member in members:
            perm_member_rd[member] = discord.PermissionOverwrite(view_channel=True, send_messages=False, read_messages=True)
            perm_member[member] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_messages=True)
        
        perm_member_rd[ctf_user] = discord.PermissionOverwrite(view_channel=False, send_messages=False, read_messages=False)
        perm_member[ctf_user] = discord.PermissionOverwrite(view_channel=False, send_messages=False, read_messages=False)

        role = discord.utils.get(ctx.guild.roles, name=str(ctf_name))
        await role.delete()
        await ctx.respond(f"`{role.name}` role deleted, archiving channel.")

        lock_ctf = "🔒 " + ctf_name
        category = discord.utils.get(ctx.guild.categories, name=ctf_name)
        if category != None: # Checks if category exists, if it doesn't it will create it.
            # Category RDONLY
            await category.edit(name=lock_ctf, overwrites=perm_member_rd)

            # Edit RDONLY channel without general channel
            for channel in category.channels[1:]:
                name = "🔒-" + channel.name[1:]
                await channel.edit(name=name, sync_permissions=True, category=category)
            
            # read & write able
            await general_channel.edit(overwrites=perm_member)
        
            
        
        server = teamdb[str(ctx.guild.id)]
        ctf_info = {'name': lock_ctf, "category": lock_ctf}
        server.update({'name': ctf_name}, {"$set": ctf_info}, upsert=True)
    
    #### Archiving CTF Info End ####
    
    #### /ctf join ctf_name To join CTF ####
    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    async def join(self, ctx, ctf_name=discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_ctf_category))):
        # Give the user the role of whatever ctf channel they're currently in.
        role = discord.utils.get(ctx.guild.roles, name=str(ctf_name))
        user = ctx.author
        await user.add_roles(role)
        await ctx.respond(f"{user.mention} has joined the `{str(ctf_name)}` team!")

        category = discord.utils.get(ctx.guild.categories, name=str(ctf_name))
        channel = category.channels[0]
        await channel.send(f"⚔️ {user.mention} joined in Game! ⚔️")
    #### join CTF End ####
    
    #### /ctf leave ctf To leave CTF ####
    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def leave(self, ctx, ctf_name=discord.Option(str, autocomplete=discord.utils.basic_autocomplete(get_joined_ctf))):
        # Remove from the user the role of the ctf channel they're currently in.
        role = discord.utils.get(ctx.guild.roles, name=str(ctf_name))
        user = ctx.author
        await user.remove_roles(role)
        await ctx.respond(f"{user.mention} has left the {str(ctf_name)} team. 👋")
    #### leave CTF End ####

    ###############################
    #### Sub Command Challenge ####
    ###############################
    challenge = ctf.create_subgroup("challenge", description="Challenge Utils", guild_ids=[guild_id])
    
    @staticmethod
    def updateChallenge(ctx, name, status):
        # Update the db with a new challenge and its status
        server = teamdb[str(ctx.guild.id)]
        whitelist = set(string.ascii_letters+string.digits+' '+'-'+'!'+'#'+'_'+'['+']'+'('+')'+'?'+'@'+'+'+'<'+'>')
        challenge = {strip_string(str(name), whitelist): status}
        ctf = server.find_one({'name': str(ctx.message.channel)})
        try: # If there are existing challenges already...
            challenges = ctf['challenges']
            challenges.update(challenge)
        except:
            challenges = challenge
        ctf_info = {'name': str(ctx.message.channel),
        'challenges': challenges
        }
        server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)

    
    @challenge.command()
    @in_ctf_channel()
    async def add(self, ctx, name):
        CTF.updateChallenge(ctx, name, 'Unsolved')
        await ctx.respond(f"`{name}` has been added to the challenge list for `{str(ctx.message.channel)}`")
    
    @challenge.command()
    @in_ctf_channel()
    async def solved(self, ctx, name):
        solve = f"Solved - {str(ctx.message.author)}"
        CTF.updateChallenge(ctx, name, solve)
        await ctx.respond(f":triangular_flag_on_post: `{name}` has been solved by `{str(ctx.message.author)}`")
    
    @challenge.command()
    @in_ctf_channel()
    async def working(self, ctx, name):
        work = f"Working - {str(ctx.message.author)}"
        CTF.updateChallenge(ctx, name, work)
        await ctx.respond(f"`{str(ctx.message.author)}` is working on `{name}`!")
    
    @challenge.command(aliases=['r', 'delete', 'd'])
    @in_ctf_channel()
    async def remove(self, ctx, name):
        # Typos can happen (remove a ctf challenge from the list)
        ctf = teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)})
        challenges = ctf['challenges']
        whitelist = set(string.ascii_letters+string.digits+' '+'-'+'!'+'#'+'_'+'['+']'+'('+')'+'?'+'@'+'+'+'<'+'>')
        name = strip_string(name, whitelist)
        challenges.pop(name, None)
        ctf_info = {'name': str(ctx.message.channel),
        'challenges': challenges
        }
        teamdb[str(ctx.guild.id)].update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
        await ctx.respond(f"Removed `{name}`")
    
    @challenge.command(aliases=['get', 'ctfd'])
    @in_ctf_channel()
    async def pull(self, ctx, url):
        # Pull challenges from a ctf hosted on the CTFd platform
        try:
            try:
                # Get the credentials from the pinned message
                pinned = await ctx.message.channel.pins()
                user_pass = CTF.get_creds(pinned)
            except CredentialsNotFound as cnfm:
                await ctx.respond(cnfm)
            ctfd_challs = getChallenges(url, user_pass[0], user_pass[1])
            ctf = teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)})
            try: # If there are existing challenges already...
                challenges = ctf['challenges']
                challenges.update(ctfd_challs)
            except:
                challenges = ctfd_challs
            ctf_info = {'name': str(ctx.message.channel),
            'challenges': challenges
            }
            teamdb[str(ctx.guild.id)].update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
            await ctx.message.add_reaction("✅")
        except InvalidProvider as ipm:
            await ctx.respond(ipm)
        except InvalidCredentials as icm:
            await ctx.respond(icm)
        except NonceNotFound as nnfm:
            await ctx.respond(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.respond("Supply a valid url in the form: `http(s)://ctfd.url`")
        except:
            traceback.print_exc()


    #### Set Credit ####
    @commands.bot_has_permissions(manage_messages=True)
    @commands.has_permissions(manage_messages=True)
    @ctf.command()
    @in_ctf_channel()
    async def setcreds(self, ctx, 
                       ctf_platform: discord.Option(str, description="✅ Automatic Detected Platform", autocomplete=discord.utils.basic_autocomplete(get_credential_type)), # type: ignore
                       username: discord.Option(str, description="for `CTFd` Platform", required=False), # type: ignore
                       password: discord.Option(str, description="for `CTFd` Platform", required=False), # type: ignore
                       invite_code: discord.Option(str, description="for `rCTF` Platform", required=False)): # type: ignore
        # Creates a pinned message with the credntials supplied by the user
        category = ctx.interaction.channel.category
        platform = ["CTFd", "rCTF"]
        message = ""
        link = ""

        for ctf in ctfs.find():
            if ctf['name'] == category.name:
                link = ctf['url']
                break

        await ctx.respond("✅ Account Info Created.")

        message += f":ballot_box_with_check: CTF Platform is `{ctf_platform}`\n\n"

        for channel in category.channels:
            if 'account' in channel.name:
                if ctf_platform == platform[0]:
                    message += f":triangular_flag_on_post: CTF Link: {link}\n\n"
                    message += f":unlock: Account info to Login\n\n"
                    message += f"```ruby\n"
                    message += f"Username: {username}\n"
                    message += f"Password: {password}\n"
                    message += f"```\n"
                else:
                    message += f":triangular_flag_on_post: CTF Link: `{link}`\n\n"
                    message += f":unlock: Account info to Login\n\n"
                    message += f"- *Invite Code*\n\n"
                    message += f"> {invite_code}\n\n"

                break

        await channel.send(message)
    #### Set Credit End ####
    

    @staticmethod
    def gen_page(challengelist):
        # Function for generating each page (message) for the list of challenges in a ctf.
        challenge_page = ""
        challenge_pages = []
        for c in challengelist:
            # Discord message sizes cannot exceed 2000 characters.
            # This will create a new message every 2k characters.
            if not len(challenge_page + c) >= 1989:
                challenge_page += c
                if c == challengelist[-1]: # if it is the last item
                    challenge_pages.append(challenge_page)
            
            elif len(challenge_page + c) >= 1989:
                challenge_pages.append(challenge_page)
                challenge_page = ""
                challenge_page += c

        # print(challenge_pages)
        return challenge_pages

    @challenge.command()
    @in_ctf_channel()
    async def list(self, ctx):
        # list the challenges in the current ctf.
        ctf_challenge_list = []
        server = teamdb[str(ctx.guild.id)]
        ctf = server.find_one({'name': str(ctx.message.channel)})
        try:
            ctf_challenge_list = []
            for k, v in ctf['challenges'].items():
                challenge = f"[{k}]: {v}\n"
                ctf_challenge_list.append(challenge)
            
            for page in CTF.gen_page(ctf_challenge_list):
                await ctx.respond(f"```ini\n{page}```")
                # ```ini``` makes things in '[]' blue which looks nice :)
        except KeyError as e: # If nothing has been added to the challenges list
            await ctx.respond("Add some challenges with `/ctf challenge add \"challenge name\"`")
        except:
            traceback.print_exc()

def setup(bot):
    bot.add_cog(CTF(bot))