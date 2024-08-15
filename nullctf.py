import discord
import config_vars

intents = discord.Intents.all()
bot = discord.Bot(intents=intents,)

@bot.event
async def on_ready():
    print(f"{bot.user.name} - Online")
    print(f"discord.py {discord.__version__}\n")
    print("-------------------------------")

    await bot.change_presence(activity=discord.Game(name=">help | >source"))

extensions = ['cogs.ping', 'cogs.ctftime', 'cogs.ctf']

if __name__ == '__main__':
    for extension in extensions:
        bot.load_extension(extension)

bot.run(config_vars.discord_token)