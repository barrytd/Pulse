# pulse/known_good.py
# --------------------
# Built-in list of known-legitimate Windows service names.
#
# These are suppressed by default so common software doesn't flood reports
# with false positives. Users can still add their own entries in pulse.yaml.
#
# HOW MATCHING WORKS:
#   Each entry is checked as a case-insensitive substring of the finding's
#   details string. So "corsair" matches "Corsair Gaming Audio Service",
#   "Corsair Bus", "Corsair iCUE Update Service", etc.
#
#   Be specific enough that you won't accidentally suppress real malware.
#   For example, don't add "service" — add "Corsair" or "Google Updater".

KNOWN_GOOD_SERVICES = [

    # -------------------------------------------------------------------------
    # ANTI-CHEAT ENGINES
    # Installed and removed automatically every time certain games launch.
    # -------------------------------------------------------------------------
    "vgc",                          # Valorant anti-cheat (Riot)
    "vgk",                          # Valorant kernel driver (Riot)
    "battleye service",             # BattlEye anti-cheat
    "bedaisy",                      # BattlEye kernel driver
    "easyanticheat",                # Easy Anti-Cheat (Epic)
    "easy anti-cheat",              # Easy Anti-Cheat display name
    "eaanticheatservice",           # EA anti-cheat
    "eaanticheat",                  # EA anti-cheat variants
    "player location check",        # Riot Games (Valorant)
    "faceit",                       # FACEIT anti-cheat
    "esea",                         # ESEA anti-cheat
    "xigncode",                     # XIGNCODE3 anti-cheat
    "nprotect",                     # nProtect GameGuard
    "gameguard",                    # GameGuard anti-cheat
    "mhyprot",                      # Genshin Impact / HoYoverse anti-cheat
    "ricochet",                     # Call of Duty Ricochet anti-cheat

    # -------------------------------------------------------------------------
    # GAMING PLATFORMS & LAUNCHERS
    # -------------------------------------------------------------------------
    "gaming services",              # Xbox / Microsoft Gaming Services
    "gameinput redist service",     # Xbox GameInput
    "gameinput",                    # Xbox GameInput variants
    "battle.net update helper",     # Blizzard Battle.net
    "blizzard",                     # Blizzard Entertainment services
    "ubisoft upc elevation",        # Ubisoft Connect
    "ubisoft game launcher",        # Ubisoft launcher
    "steam client service",         # Valve Steam
    "origin",                       # EA Origin / EA App
    "ea app",                       # EA App (Origin successor)
    "epicgames",                    # Epic Games Launcher
    "epic games",                   # Epic Games services
    "bethesda",                     # Bethesda.net Launcher
    "rockstar games",               # Rockstar Games Launcher
    "gog",                          # GOG Galaxy
    "playnite",                     # Playnite game manager
    "xbox live",                    # Xbox Live services
    "xboxnetapisvc",                # Xbox networking

    # -------------------------------------------------------------------------
    # HARDWARE MONITORING & PERIPHERALS
    # -------------------------------------------------------------------------
    # Corsair iCUE
    "corsair",                      # matches all Corsair services
    "icue",                         # Corsair iCUE plugin host

    # Razer Synapse
    "razer",                        # matches all Razer services
    "haptic service",               # Razer haptics

    # Logitech
    "logitech",                     # Logitech G HUB / Options
    "lghub",                        # Logitech G HUB

    # NZXT CAM
    "cam service",                  # NZXT CAM
    "ksld",                         # NZXT CAM kernel driver
    "nzxt",                         # NZXT services

    # SteelSeries
    "steelseries",                  # SteelSeries GG / Engine

    # HyperX / Kingston
    "hyperx",                       # HyperX NGENUITY
    "ngenuity",                     # HyperX NGENUITY service

    # ASUS
    "asus",                         # ASUS Armory Crate / Aura
    "armory crate",                 # ASUS Armory Crate
    "aura",                         # ASUS Aura Sync (careful — too generic alone)

    # MSI
    "msi center",                   # MSI Center
    "dragon center",                # MSI Dragon Center (older)

    # CPU-Z / hardware probes
    "cpuz",                         # CPU-Z hardware probe (all versions)

    # Fan/thermal controllers
    "argus monitor",                # Argus Monitor
    "hwinfo",                       # HWiNFO sensor service
    "openhardwaremonitor",          # Open Hardware Monitor
    "libre hardware monitor",       # LibreHardwareMonitor

    # -------------------------------------------------------------------------
    # GOOGLE SOFTWARE
    # -------------------------------------------------------------------------
    "google updater",               # matches all Google Updater versions
    "google play games",            # matches all Google Play Games versions
    "google chrome",                # Chrome update service
    "googlechrome",                 # Chrome variants
    "google drive",                 # Google Drive / Backup and Sync
    "google earth",                 # Google Earth
    "googlecrashhandler",           # Google crash reporting

    # -------------------------------------------------------------------------
    # MICROSOFT / WINDOWS BUILT-IN
    # -------------------------------------------------------------------------
    "microsoft office click-to-run",    # Office updates
    "microsoft teams",                  # Teams service
    "microsoft edge update",            # Edge updater
    "microsoft onedrive",               # OneDrive sync
    "onedrive",                         # OneDrive variants
    "windows update",                   # Windows Update
    "wuauserv",                         # Windows Update service name
    "windows defender",                 # Windows Defender / Microsoft Defender
    "microsoft defender",               # Microsoft Defender
    "wscsvc",                           # Windows Security Center
    "securityhealthservice",            # Windows Security Health
    "microsoft visual c++",             # VC++ redistributable services
    "microsoft .net",                   # .NET Framework
    "dotnet",                           # .NET services
    "visual studio",                    # Visual Studio services
    "vss",                              # Volume Shadow Copy Service

    # -------------------------------------------------------------------------
    # REMOTE ACCESS & COLLABORATION
    # -------------------------------------------------------------------------
    "chrome remote desktop",            # Google Chrome Remote Desktop
    "teamviewer",                       # TeamViewer
    "anydesk",                          # AnyDesk (note: also used by attackers)
    "parsec",                           # Parsec remote gaming
    "sunshine",                         # Sunshine game streaming
    "moonlight",                        # Moonlight game streaming

    # -------------------------------------------------------------------------
    # SECURITY & ANTIVIRUS SOFTWARE
    # -------------------------------------------------------------------------
    "malwarebytes",                     # Malwarebytes
    "mbamservice",                      # Malwarebytes service name
    "avast",                            # Avast Antivirus
    "avastantivirus",                   # Avast service
    "avg ",                             # AVG Antivirus (note space to avoid "average")
    "avgantivirus",                     # AVG service
    "bitdefender",                      # Bitdefender
    "kaspersky",                        # Kaspersky
    "norton",                           # Norton / NortonLifeLock
    "mcafee",                           # McAfee
    "eset",                             # ESET NOD32
    "trend micro",                      # Trend Micro
    "sophos",                           # Sophos
    "webroot",                          # Webroot
    "cylance",                          # Cylance
    "crowdstrike",                      # CrowdStrike Falcon

    # -------------------------------------------------------------------------
    # COMMON SOFTWARE
    # -------------------------------------------------------------------------
    "claude",                           # Claude desktop app (Anthropic)
    "discord",                          # Discord update service
    "spotify",                          # Spotify
    "slack",                            # Slack
    "zoom",                             # Zoom
    "obs studio",                       # OBS Studio
    "obs-studio",                       # OBS variants
    "nvidia",                           # NVIDIA drivers / GeForce Experience
    "geforce",                          # NVIDIA GeForce
    "amd",                              # AMD drivers / Radeon Software
    "radeon",                           # AMD Radeon Software
    "intel",                            # Intel driver services
    "realtek",                          # Realtek audio drivers
    "nahimic",                          # Nahimic audio
    "sonic studio",                     # ASUS Sonic Studio audio
    "voicemeeter",                      # VoiceMeeter audio mixer
    "equalizer apo",                    # Equalizer APO
    "7zip",                             # 7-Zip
    "winrar",                           # WinRAR
    "ccleaner",                         # CCleaner
    "dropbox",                          # Dropbox
    "box ",                             # Box sync
    "adobe",                            # Adobe software (Acrobat, Creative Cloud)
    "creative cloud",                   # Adobe Creative Cloud
    "autodesk",                         # Autodesk software
    "vmware",                           # VMware Workstation / Player
    "virtualbox",                       # Oracle VirtualBox
    "docker",                           # Docker Desktop
    "tailscale",                        # Tailscale VPN
    "nordvpn",                          # NordVPN
    "expressvpn",                       # ExpressVPN
    "mullvad",                          # Mullvad VPN
    "protonvpn",                        # ProtonVPN
    "wireguard",                        # WireGuard VPN
    "ipvanish",                         # IPVanish VPN
    "private internet access",          # PIA VPN
]
