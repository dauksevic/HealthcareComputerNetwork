--------------------- MODULE HealthcareComputerNetwork ---------------------

EXTENDS     Definitions,
            Integers, 
            FiniteSets

VARIABLES   zoneCompromised,
            zoneState,
            activeSER,
            reconfigurationCompleted,
            compromiseDetected

vars == << zoneCompromised, zoneState, activeSER, reconfigurationCompleted, compromiseDetected >>

ZoneTrustLevel(z) ==
    CASE z = "Guest"        -> "PZ"
      [] z = "DMZ"          -> "PAZ"
      [] z = "Enterprise"   -> "OZ"
      [] z = "Lab"          -> "OZ"
      [] z = "Core"         -> "AZ"
      [] z = "Database"     -> "AZ"
      [] z = "Backup"       -> "CZ"
      [] z = "Clinical"     -> "CZ"
      [] z = "IoMT"         -> "CZ"
   
NetworkMode ==
    CASE (\A z \in Zones : zoneState[z] = "Secure") 
         -> "Secure"
      [] (\E z \in Zones : zoneState[z] = "Isolated" /\ ZoneTrustLevel(z) \in {"AZ", "CZ"}) 
         -> "Reconfiguring"
      [] (/\ \E z \in Zones : zoneState[z] = "Isolated"
          /\ \A z \in Zones : (zoneState[z] \notin {"Secure", "Reconnecting"}) => ZoneTrustLevel(z) \in {"PZ", "PAZ", "OZ"})
         -> "Operational"
      [] (/\ \E z \in Zones : zoneState[z] = "Reconnecting"
          /\ ~(\E z \in Zones : zoneState[z] = "Isolated")
          /\ \A z \in Zones : zoneState[z] \in {"Secure", "Reconnecting"}) 
         -> "Recovering"
      [] OTHER 
         -> "Undefined"

BackupMode ==    
    CASE (\E z \in Zones : ZoneTrustLevel(z) \in {"AZ", "CZ"} /\ zoneState[z] # "Secure") 
        -> "Reconfiguration"
    [] OTHER 
        -> "Idle"
     
TypeOK ==
    /\ zoneCompromised      \in         [Zones -> BOOLEAN   ]
    /\ zoneState            \in         [Zones -> ZoneStates]
    /\ activeSER            \subseteq   SER \cup SER_backupReconfig \cup SER_backupIdle \cup SER_AZ_CZ
    /\ compromiseDetected   \in         BOOLEAN
    /\ NetworkMode         #           "Undefined"
       
IsolationApplied(z) ==
    LET tl == ZoneTrustLevel(z) IN
    \/ /\ tl \in {"PZ", "PAZ", "OZ"}
       /\ \A ser \in (SER \cup SER_backupIdle \cup SER_backupReconfig \cup SER_AZ_CZ) : (ser.src = z \/ ser.dst = z) => ser \notin activeSER
       
    \/ /\ tl = "AZ"
       /\ \A ser \in (SER \cup SER_backupIdle \cup SER_backupReconfig \cup SER_AZ_CZ) :
            /\ (ser.dst = z /\ ZoneTrustLevel(ser.src) \in {"PZ", "PAZ"}) => ser \notin activeSER
            /\ (ser.src = z /\ ZoneTrustLevel(ser.dst) \in {"PZ", "PAZ"}) => ser \notin activeSER
            /\ (ser.src = z /\ ZoneTrustLevel(ser.dst) = "OZ" /\ ser.maxSens \notin {"Public", "Internal"}) => ser \notin activeSER
            /\ (ZoneTrustLevel(ser.src) = "AZ" /\ ZoneTrustLevel(ser.dst) = "CZ") => ser \notin activeSER
            /\ (ZoneTrustLevel(ser.src) = "CZ" /\ ZoneTrustLevel(ser.dst) = "AZ") => ser \notin activeSER
            
    \/ /\ tl = "CZ"
       /\ \A ser \in (SER \cup SER_backupIdle \cup SER_backupReconfig \cup SER_AZ_CZ) :
            /\ (ser.src = z /\ ZoneTrustLevel(ser.dst) \in {"PZ", "PAZ", "OZ", "AZ"}) => ser \notin activeSER
            /\ (ser.dst = z /\ ZoneTrustLevel(ser.src) \in {"PZ", "PAZ", "OZ", "AZ"}) => ser \notin activeSER

IsolationInvariant ==
  \A z \in Zones :
     zoneState[z] = "Isolated" => IsolationApplied(z)

NetworkModeConsistency ==
    /\ (NetworkMode = "Secure") <=>
        (\A z \in Zones : zoneState[z] = "Secure")
    
    /\ (NetworkMode = "Reconfiguring") <=>
        (\E z \in Zones : zoneState[z] = "Isolated" /\ ZoneTrustLevel(z) \in {"AZ", "CZ"})
    
    /\ (NetworkMode = "Operational") <=>
        (/\   \E z \in Zones : zoneState[z] = "Isolated"
         /\ ~(\E z \in Zones : zoneState[z] = "Isolated" /\ ZoneTrustLevel(z) \in {"AZ", "CZ"}))
    
    /\ (NetworkMode = "Recovering") <=>
        (/\   \E z \in Zones : zoneState[z] = "Reconnecting"
         /\ ~(\E z \in Zones : zoneState[z] = "Isolated"))
  
Init ==
    /\ zoneCompromised          = [z \in Zones |-> FALSE]         
    /\ zoneState                = [z \in Zones |-> "Secure"]
    /\ activeSER                = SER \cup SER_backupIdle \cup SER_AZ_CZ        
    /\ reconfigurationCompleted = FALSE
    /\ compromiseDetected       = FALSE
    
DetectCompromise(z) ==
    /\ ~compromiseDetected
    /\ ~zoneCompromised[z]
    /\ zoneCompromised' = [zoneCompromised EXCEPT ![z] = TRUE]
    /\ compromiseDetected' = TRUE
    /\ UNCHANGED << zoneState, activeSER, reconfigurationCompleted >>

Expansion(from, to) ==
    /\ compromiseDetected
    /\ zoneCompromised[from]
    /\ \E ser \in activeSER : ser.src = from /\ ser.dst = to
    /\ ~zoneCompromised[to]
    /\ zoneCompromised' = [zoneCompromised EXCEPT ![to] = TRUE]
    /\ UNCHANGED << zoneState, activeSER, reconfigurationCompleted, compromiseDetected >>

RemediateZones ==
    /\ \E z \in Zones : zoneCompromised[z] /\ zoneState[z] = "Isolated"
    /\ zoneCompromised' = 
        [z \in Zones |->
            IF zoneCompromised[z] /\ zoneState[z] = "Isolated"
            THEN FALSE
            ELSE zoneCompromised[z]]
    /\ UNCHANGED << zoneState, activeSER, reconfigurationCompleted, compromiseDetected >>

IsolateLowTrustZone(z) ==
    LET tl == ZoneTrustLevel(z) IN
    /\ tl \in {"PZ", "PAZ", "OZ"}
    /\ zoneCompromised[z]
    /\ zoneState[z] # "Isolated"
    /\ activeSER' = {ser \in activeSER : ser.src # z /\ ser.dst # z}
    /\ zoneState' = [zoneState EXCEPT ![z] = "Isolated"]
    /\ UNCHANGED << zoneCompromised, reconfigurationCompleted, compromiseDetected >>

IsolateAdministrationZone(z) ==
    /\ ZoneTrustLevel(z) = "AZ"
    /\ zoneCompromised[z]
    /\ zoneState[z] # "Isolated"
    /\ activeSER' = {ser \in activeSER :
        /\ ~(ser.dst = z /\ ZoneTrustLevel(ser.src) \in {"PZ", "PAZ"})
        /\ ~(ser.src = z /\ ZoneTrustLevel(ser.dst) \in {"PZ", "PAZ"})
        /\ ~(ser.src = z /\ ZoneTrustLevel(ser.dst) = "OZ" /\ ser.maxSens \notin {"Public", "Internal"})
        /\ ~(ZoneTrustLevel(ser.src) = "AZ" /\ ZoneTrustLevel(ser.dst) = "CZ")
        /\ ~(ZoneTrustLevel(ser.src) = "CZ" /\ ZoneTrustLevel(ser.dst) = "AZ")} \cup SER_backupReconfig
    /\ zoneState' = [zoneState EXCEPT ![z] = "Isolated"]
    /\ UNCHANGED << zoneCompromised, reconfigurationCompleted, compromiseDetected >>

IsolateCriticalZone(z) ==
    /\ ZoneTrustLevel(z) = "CZ"
    /\ zoneCompromised[z]
    /\ zoneState[z] # "Isolated"
    /\ activeSER' = {ser \in activeSER :
        /\ ~(ZoneTrustLevel(ser.src) = "CZ" /\ ZoneTrustLevel(ser.dst) \in {"PZ", "PAZ", "OZ", "AZ"})
        /\ ~(ZoneTrustLevel(ser.dst) = "CZ" /\ ZoneTrustLevel(ser.src) \in {"PZ", "PAZ", "OZ", "AZ"})} \cup SER_backupReconfig
    /\ zoneState' = [zoneState EXCEPT ![z] = "Isolated"]
    /\ UNCHANGED << zoneCompromised, reconfigurationCompleted, compromiseDetected >>

RecoverZones ==
    /\ \E z \in Zones : (zoneState[z] = "Isolated" /\ ~zoneCompromised[z])
    /\ zoneState' = [z \in Zones |->
        IF zoneState[z] = "Isolated" /\ ~zoneCompromised[z]
        THEN "Reconnecting"
        ELSE zoneState[z]]
    /\ UNCHANGED <<zoneCompromised, activeSER, reconfigurationCompleted, compromiseDetected >>

RestoreSER ==
    /\ \E ser \in ( SER \ activeSER) :
        /\ zoneState[ser.src] \in {"Secure", "Reconnecting"}
        /\ zoneState[ser.dst] \in {"Secure", "Reconnecting"}
        /\ \/ NetworkMode # "Reconfiguring"
           \/ /\ ZoneTrustLevel(ser.src) = "CZ"
              /\ ZoneTrustLevel(ser.dst) = "CZ"
        /\ activeSER' = activeSER \cup {ser}
    /\ UNCHANGED <<zoneCompromised, zoneState, reconfigurationCompleted, compromiseDetected >>

RestoreAllSER ==
    LET possibleSER == { ser \in ( SER \ activeSER) :
        /\ zoneState[ser.src] \in {"Secure", "Reconnecting"}
        /\ zoneState[ser.dst] \in {"Secure", "Reconnecting"}
        /\ \/ NetworkMode # "Reconfiguring"
           \/ /\ ZoneTrustLevel(ser.src) = "CZ"
              /\ ZoneTrustLevel(ser.dst) = "CZ" } IN
    /\ possibleSER # {}
    /\ activeSER' = activeSER \cup possibleSER
    /\ UNCHANGED <<zoneCompromised, zoneState, reconfigurationCompleted, compromiseDetected >>

TransitionToSecure ==
    /\ \E z \in Zones : (zoneState[z] = "Reconnecting" /\ \A ser \in SER : (ser.src = z \/ ser.dst = z) => ser \in activeSER)
    /\ LET newZoneState == [z \in Zones |->
            IF zoneState[z] = "Reconnecting" /\ \A ser \in SER : (ser.src = z \/ ser.dst = z) => ser \in activeSER
            THEN "Secure"
            ELSE zoneState[z]]
           allAZCZSecure == \A z \in Zones : ZoneTrustLevel(z) \in {"AZ", "CZ"} => newZoneState[z] = "Secure"
       IN
       /\ zoneState' = newZoneState
       /\ activeSER' = IF allAZCZSecure
                       THEN (activeSER \ SER_backupReconfig) \cup SER_backupIdle \cup SER_AZ_CZ
                       ELSE activeSER
       /\ UNCHANGED <<zoneCompromised, reconfigurationCompleted, compromiseDetected >>

MarkReconfigurationComplete ==
    /\ NetworkMode = "Secure"
    /\ \E z \in Zones : ZoneTrustLevel(z) = "AZ" /\ zoneState[z] = "Secure"
    /\ ~reconfigurationCompleted
    /\ reconfigurationCompleted' = TRUE
    /\ UNCHANGED << zoneCompromised, zoneState, activeSER, compromiseDetected >>

Next ==
    \/ \E z      \in Zones : DetectCompromise(z)
    \/ \E z1, z2 \in Zones : Expansion(z1, z2)
    \/ \E z      \in Zones : IsolateLowTrustZone(z)
    \/ \E z      \in Zones : IsolateAdministrationZone(z)
    \/ \E z      \in Zones : IsolateCriticalZone(z)    
    \/ RemediateZones
    \/ RecoverZones    
    \/ TransitionToSecure
    \/ RestoreAllSER
    \/ MarkReconfigurationComplete

DP2_CriticalAvailability ==
    /\ [src |-> "Clinical", dst |-> "IoMT",             maxSens |-> "Restricted"]   \in activeSER
    /\ [src |-> "IoMT",     dst |-> "Clinical",         maxSens |-> "Restricted"]   \in activeSER
    /\ \/ (/\ [src |-> "Clinical",  dst |-> "Core",     maxSens |-> "Restricted"]   \in activeSER
           /\ [src |-> "Core",      dst |-> "Clinical", maxSens |-> "Restricted"]   \in activeSER
           /\ [src |-> "Core",      dst |-> "Database", maxSens |-> "Restricted"]   \in activeSER
           /\ [src |-> "Database",  dst |-> "Core",     maxSens |-> "Restricted"]   \in activeSER)
       \/ (/\ [src |-> "Clinical",  dst |-> "Backup",   maxSens |-> "Restricted"]   \in activeSER
           /\ [src |-> "Backup",    dst |-> "Clinical", maxSens |-> "Restricted"]   \in activeSER)

DP3_BackupAdaptiveness == 
    \/ /\ BackupMode = "Idle"
       /\ SER_backupReconfig \ activeSER = SER_backupReconfig
       /\ SER_backupIdle \subseteq activeSER
    \/ /\ BackupMode = "Reconfiguration" 
       /\ SER_backupReconfig \subseteq activeSER
       /\ SER_backupIdle \ activeSER = SER_backupIdle

DP1_DynamicReconfiguration ==
    []((\E z \in Zones : zoneCompromised[z] /\ ZoneTrustLevel(z) \in {"AZ", "CZ"}) 
       => <>(NetworkMode = "Reconfiguring"))

StateConstraint ==
    /\ Cardinality({z \in Zones : zoneCompromised[z]}) \leq 3
    /\ ~reconfigurationCompleted

Spec == Init /\ [][Next]_vars

FairSpec == 
    /\ Spec 
    /\ \A z \in Zones : SF_vars(IsolateLowTrustZone(z))
    /\ \A z \in Zones : SF_vars(IsolateAdministrationZone(z))
    /\ \A z \in Zones : SF_vars(IsolateCriticalZone(z))
    /\ SF_vars(RemediateZones)
    /\ SF_vars(RecoverZones)
    /\ SF_vars(TransitionToSecure)
    /\ WF_vars(RestoreAllSER)
    /\ WF_vars(MarkReconfigurationComplete)

============================================================================
\* Modification History
\* Last modified Fri Feb 20 13:00:02 EET 2026 by DanielDauksevic
\* Created       Sun Feb 15 19:04:24 EET 2026 by DanielDauksevic