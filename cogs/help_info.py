
ctftime_help = {
    "/ctftime upcoming [1-5]": "return info on a number of upcoming ctfs from ctftime.org",
    "/ctftime countdown": "return specific times for the time until a ctf begins",
    "/ctftime current": "return info on the currently running ctfs on ctftime.org",
    "/ctftime top [year]": "display the leaderboards from ctftime from a certain year.",
    "/ctftime timeleft": "return until a currently running ctf ends"
}

ctf_help = {
    "/ctf archive": "archive CTF and lock all channel without general",
    "/ctf create \"CTF NAME\"":"create a text channel and role in the CTF category for a ctf (must have permissions to manage channels)*",
    "/ctf delete": "delete the ctf role, and entry from the database for the ctf (must have permissions to manage channels)*",
    "/ctf join": "give role and join in CTF Channel",
    "/ctf leave": "delete role about leave CTF",
    "/ctf setcreds \"platform\" [username] [password] [invite_code]": "set accounts info",
    "/ctf solve": "Solve challenge update after challenge solved",
    "/ctf workon": "join the challenge thread",
    "/ctf challenge pull [https://ctfd.url]": "will add all of the challenges on the provided CTFd CTF and add them to your challenge list, including solve state."
}

config_help = '''

`/config ctf_category "CTF CATEGORY"`
specify the category to be used for CTF channels, defaults to "CTF".

`/config archive_category "ARCHIVE CATEGORY"`
specify the category to be used for archived CTF channels, defaults to "Archive".
'''

utility_help = '''
`/magicb [filetype]`
return the magicbytes/file header of a supplied filetype.
`/rot "message"`
return all 25 different possible combinations for the popular caesar cipher - use quotes for messages more than 1 word
`/b64 [encode/decode] "message"`
encode or decode in base64 - if message has spaces use quotations
`/b32 [encode/decode] "message"`
encode or decode in base32 - if message has spaces use quotations
`/binary [encode/decode] "message"`
encode or decode in binary - if message has spaces use quotations
`/hex [encode/decode] "message"`
encode or decode in hex - if message has spaces use quotations
`/url [encode/decode] "message"`
encode or decode based on url encoding - if message has spaces use quotations
`/reverse "message"`
reverse the supplied string - if message has spaces use quotations
`/counteach "message"`
count the occurences of each character in the supplied message - if message has spaces use quotations
`/characters "message"`
count the amount of characters in your supplied message
`/wordcount "phrase"`
count the amount of words in your supplied message
`/atbash "message"`
encode or decode in the atbash cipher - if message has spaces use quotations (encode/decode do the same thing)
`/github [user]`
get a direct link to a github profile page with your supplied user
`/twitter [user]`
get a direct link to a twitter profile page with your supplied user
`/cointoss`
get a 50/50 cointoss to make all your life's decisions
`/amicool`
for the truth.
'''


help_page = {
    '/help ctftime': "Show information for **all ctftime commands**",
    '/help ctf': "Show information for **all ctf commands**"
}


src = "https://github.com/NullPxl/NullCTF"