import discord
import config_vars
import os, sys

intents = discord.Intents.all()
bot = discord.Bot(intents=intents,)
extensions = ['ping', 'ctftime', 'ctf', 'help',]

@bot.event
async def on_ready():
    print(f"{bot.user.name} - Online")
    print(f"discord.py {discord.__version__}\n")
    print("-------------------------------")

    await bot.change_presence(activity=discord.Game(name="/help"))


if __name__ == '__main__':
    sys.path.insert(1, os.getcwd() + '/cogs/')
    for extension in extensions:
        try:
            bot.load_extension(extension)
        except Exception as e:
            print(f'Failed to load cogs : {e}')

    bot.run(config_vars.discord_token)