"""
Branding configuration — all name/identity constants live here.
To rename the tool: change TOOL_NAME, TOOL_TAGLINE, and ASCII_ART below.
See README.md § Rebranding Guide for the full checklist.
"""

TOOL_NAME = "Argus"
TOOL_VERSION = "1.0.0"
TOOL_TAGLINE = "web vulnerability scanner"
TOOL_LEGAL = "For authorized testing only. Unauthorized scanning is illegal."
TOOL_COLOR = "bright_cyan"  # Rich color for the ASCII banner

# To regenerate: https://patorjk.com/software/taag/ (font: ANSI Shadow)
ASCII_ART = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"""
