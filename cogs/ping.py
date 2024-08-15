import discord
from discord.ext import commands
from discord import slash_command
import config_vars

class Ping(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(guild_ids=[config_vars.guild_id], name='ping', description='pong')
    async def ping(self, ctx: discord.ApplicationContext):
        await ctx.respond(f"pong! ({self.bot.latency*1000:.2f} ms)")

def setup(bot):
    bot.add_cog(Ping(bot))
