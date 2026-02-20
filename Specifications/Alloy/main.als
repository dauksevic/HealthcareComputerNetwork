open signatures

open util/ordering[DataSensitivity]
open util/ordering[TrustLevel]

fun pathZones[p : Path] : set Zone
{
	{ z : Zone | some i : p.hops.inds | p.hops[i].src = z or p.hops[i].dst = z }
}

fun pathSensitivity[p : Path] : DataSensitivity
{
	min[ { s : DataSensitivity | some i : p.hops.inds | p.hops[i].maxSensitivity = s } ]
}

fun serEdge : Zone -> Zone 
{
	{ z1, z2: Zone | some r: SecurityEnforcementRule | r.src = z1 and r.dst = z2 }
}

fact PathEndpoints {
    all p : Path | 
        p.src = p.hops.first.src and
        p.dst = p.hops.last.dst
}

fact DataSensitivityOrder
{
	lt[Public, Internal] and
	lt[Internal, Confidential] and
	lt[Confidential, Restricted]
}

fact TrustLevelOrder
{
	lt[PZ, PAZ] and
	lt[PAZ, OZ] and
	lt[OZ, RZ]
}

fact DeviceDistribution
{
	all z : Zone | #{ d : Device | d.zone = z } > 4
}

fact PathComposability
{
	all p : Path | all i : p.hops.inds | (i.next in p.hops.inds) implies p.hops[i].dst = p.hops[i.next].src
}

fact PathNotEmpty
{
	all p : Path | #p.hops > 0
}

fact PathAcyclicity
{
    all p : Path | 
        no disj i, j : p.hops.inds | 
            (p.hops[i].src = p.hops[j].src or 
             p.hops[i].dst = p.hops[j].dst)
}

assert SP1_Confidentiality
{ all p : Path | pathSensitivity[p] = Restricted implies
	all z : pathZones[p] | z.trustLevel != PZ and z.trustLevel != PAZ and z.trustLevel != OZ
}

assert SP2_CriticalAvailability 
{	(some p : Path | p.src = Clinical and p.dst = Database and pathSensitivity[p] = Restricted ) and
 	(some p : Path | p.src = Database and p.dst = Clinical and pathSensitivity[p] = Restricted ) and
  	(some p : Path | p.src = Clinical and p.dst = IoMT and pathSensitivity[p] = Restricted ) and
  	(some p : Path | p.src = IoMT and p.dst = Clinical and pathSensitivity[p] = Restricted )
}

assert SP3_ArchitecturalIntegrity
{	all p : Path | all r : p.hops.elems |
		r.dst.trustLevel in r.src.trustLevel.next or 
		r.src.trustLevel in r.dst.trustLevel.next or 
		r.src.trustLevel = r.dst.trustLevel
}

check SP1_Confidentiality for 45 Device
check SP2_CriticalAvailability for 45 Device
check SP3_ArchitecturalIntegrity for 45 Device

run {} for 45 Device
