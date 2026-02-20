---------------------------- MODULE Definitions ----------------------------

Zones ==
{  
    "Guest", 
    "DMZ", 
    "Enterprise", 
    "Lab", 
    "Core", 
    "Database", 
    "Backup", 
    "Clinical", 
    "IoMT"
}

TrustLevels == 
{
    "PZ", 
    "PAZ", 
    "OZ", 
    "AZ", 
    "CZ"
}

DataSensitivities == 
{
    "Public", 
    "Internal", 
    "Confidential", 
    "Restricted"
}

SER == 
{
    [   src |-> "Guest",       dst |-> "DMZ",          maxSens |-> "Public"        ],
    [   src |-> "DMZ",         dst |-> "Guest",        maxSens |-> "Public"        ],
    [   src |-> "DMZ",         dst |-> "Enterprise",   maxSens |-> "Internal"      ],
    [   src |-> "Enterprise",  dst |-> "DMZ",          maxSens |-> "Internal"      ],
    [   src |-> "Enterprise",  dst |-> "Core",         maxSens |-> "Confidential"  ],
    [   src |-> "Lab",         dst |-> "Core",         maxSens |-> "Confidential"  ],
    [   src |-> "Core",        dst |-> "Enterprise",   maxSens |-> "Confidential"  ],
    [   src |-> "Core",        dst |-> "Lab",          maxSens |-> "Confidential"  ],
    [   src |-> "Core",        dst |-> "Database",     maxSens |-> "Restricted"    ],
    [   src |-> "Database",    dst |-> "Core",         maxSens |-> "Restricted"    ],   
    [   src |-> "Clinical",    dst |-> "IoMT",         maxSens |-> "Restricted"    ],
    [   src |-> "IoMT",        dst |-> "Clinical",     maxSens |-> "Restricted"    ]
}


SER_AZ_CZ ==
{
    [   src |-> "Core",        dst |-> "Clinical",     maxSens |-> "Restricted"    ],
    [   src |-> "Clinical",    dst |-> "Core",         maxSens |-> "Restricted"    ]
}

SER_backupIdle == 
{
    [   src |-> "Database",    dst |-> "Backup",       maxSens |-> "Restricted"    ],
    [   src |-> "Backup",      dst |-> "Database",     maxSens |-> "Restricted"    ]
}

SER_backupReconfig == 
{
    [   src |-> "Backup",      dst |-> "Clinical",     maxSens |-> "Restricted"    ],
    [   src |-> "Clinical",    dst |-> "Backup",       maxSens |-> "Restricted"    ]
}

ZoneStates == 
{ 
    "Secure", 
    "Isolated", 
    "Reconnecting" 
}

NetworkStates == 
{ 
    "Secure", 
    "Operational", 
    "Reconfiguring", 
    "Recovering" 
}

=============================================================================
\* Modification History
\* Last modified Fri Feb 20 12:59:57 EET 2026 by DanielDauksevic
\* Created       Sun Feb 15 19:14:42 EET 2026 by DanielDauksevic