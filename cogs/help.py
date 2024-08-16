import discord
from discord.ext import tasks, commands
from discord import slash_command
import help_info
import string
import json
import requests
import sys
import traceback
from config_vars import *

sys.path.append("..")

def setting_embed(title: str, description: str, avatar_url: str) -> discord.Embed:
    embed = discord.Embed(
        title = title,
        description= description,
        color=discord.Colour.blurple(),
    )

    embed.set_footer(text="by. CTFBot-JB", icon_url=avatar_url)
    embed.set_author(name="CTFBot-JB", icon_url=avatar_url)
    embed.set_thumbnail(url=avatar_url)

    return embed

class Help(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @slash_command(guild_ids=[guild_id], name="help", description="help command")
    async def help(self, ctx, page=None):
        avatar_url = self.bot.user.avatar.url
        title = "How to use CTF-BOT Command?"

        if page == 'ctftime':
            title = "How to use CTF-BOT Command?"
            description= "`/help ctftime` command show usage about `/ctftime` command"
            embed = setting_embed(title, description, avatar_url)

            for cmd, info in help_info.ctftime_help.items():
                embed.add_field(name=f"`{cmd}`", value=info, inline=False)

        elif page == 'ctf':
            title = "How to use CTF-BOT Command?"
            description= "`/help ctf` command show usage about `/ctf` command"
            embed = setting_embed(title, description, avatar_url)

            for cmd, info in help_info.ctf_help.items():
                embed.add_field(name=f"`{cmd}`", value=info, inline=False)
        
        else:
            description= "`/help` command show usage each category"
            embed = setting_embed(title, description, avatar_url)

            for cmd, info in help_info.help_page.items():
                embed.add_field(name=f"`{cmd}`", value=info)

        
        await ctx.respond(":white_check_mark: Command Execution Completed!", embed=embed)

def setup(bot):
    bot.add_cog(Help(bot))