abstract sig DataSensitivity {}
one sig Public, Internal, Confidential, Restricted extends DataSensitivity {}

abstract sig TrustLevel {}
one sig PZ, PAZ, OZ, RZ extends TrustLevel {}

abstract sig Zone 
{
	trustLevel : one TrustLevel
}
one sig Guest extends Zone{} { trustLevel = PZ }
one sig DMZ extends Zone{} { trustLevel = PAZ }
one sig Enterprise extends Zone{} { trustLevel = OZ	}
one sig Lab	extends Zone{} { trustLevel = OZ }
one sig Core extends Zone{} { trustLevel = RZ }
one sig Database extends Zone{} { trustLevel = RZ }
one sig Backup extends Zone{} { trustLevel = RZ }
one sig Clinical extends Zone{} { trustLevel = RZ }
one sig IoMT extends Zone{} { trustLevel = RZ }

sig Device 
{
	zone : one Zone
}

abstract sig SecurityEnforcementRule
{
	src : one Zone,
	dst : one Zone,
	maxSensitivity : one DataSensitivity
}

one sig serGuestDMZ extends SecurityEnforcementRule{} { src = Guest and dst = DMZ and maxSensitivity = Public }
one sig serDMZGuest extends SecurityEnforcementRule{} { src = DMZ and dst = Guest and maxSensitivity = Public }
one sig serDMZEnterprise extends SecurityEnforcementRule{} { src = DMZ and dst = Enterprise and maxSensitivity = Internal }
one sig serEnterpriseCore extends SecurityEnforcementRule{} { src = Enterprise and dst = Core and maxSensitivity = Confidential }
one sig serEnterpriseDMZ extends SecurityEnforcementRule{} { src = Enterprise and dst = DMZ and maxSensitivity = Internal }
one sig serCoreEnterprise extends SecurityEnforcementRule{} { src = Core	and dst = Enterprise and maxSensitivity = Confidential }
one sig serCoreLab extends SecurityEnforcementRule{} { src = Core and dst = Lab and maxSensitivity = Confidential }
one sig serLabCore extends SecurityEnforcementRule{} { src = Lab and dst = Core and maxSensitivity = Confidential }
one sig serCoreDatabase extends SecurityEnforcementRule{} { src = Core and dst = Database and maxSensitivity = Restricted }
one sig serDatabaseCore extends SecurityEnforcementRule{} { src = Database and dst = Core and maxSensitivity = Restricted }
one sig serBackupDatabase extends SecurityEnforcementRule{} { src = Backup and dst = Database and maxSensitivity = Restricted }
one sig serDatabaseBackup extends SecurityEnforcementRule{} { src = Database	and dst = Backup and maxSensitivity = Restricted }
one sig serCoreClinical extends SecurityEnforcementRule{} { src = Core and dst = Clinical and maxSensitivity = Restricted }
one sig serClinicalCore extends SecurityEnforcementRule{} { src = Clinical and dst = Core and maxSensitivity = Restricted }
one sig serClinicalIoMT extends SecurityEnforcementRule{} { src = Clinical and dst = IoMT and maxSensitivity = Restricted }
one sig serIoMTClinical extends SecurityEnforcementRule{} { src = IoMT and dst = Clinical and maxSensitivity = Restricted }

abstract sig Path
{
	src : one Zone,
	dst : one Zone,
	hops : seq SecurityEnforcementRule
}

one sig pathGuestDMZ extends Path {} { src = Guest and dst = DMZ and hops = 0->serGuestDMZ }
one sig pathDMZGuest extends Path {} { src = DMZ and dst = Guest and hops = 0->serDMZGuest }
one sig pathDMZEnterprise extends Path {} { src = DMZ and dst = Enterprise and hops = 0->serDMZEnterprise }
one sig pathEnterpriseCore extends Path {} { src = Enterprise and dst = Core and hops = 0->serEnterpriseCore }
one sig pathEnterpriseDMZ extends Path {} { src = Enterprise and dst = DMZ and hops = 0->serEnterpriseDMZ }
one sig pathCoreEnterprise extends Path {} { src = Core and dst = Enterprise and hops = 0->serCoreEnterprise }
one sig pathCoreLab extends Path {} { src = Core and dst = Lab and hops = 0->serCoreLab }
one sig pathLabCore	extends Path {} { src = Lab and dst = Core and hops = 0->serLabCore }
one sig pathCoreDatabase extends Path {} { src = Core and dst = Database and hops = 0->serCoreDatabase }
one sig pathDatabaseCore extends Path {} { src = Database and dst = Core and hops = 0->serDatabaseCore }
one sig pathBackupDatabase extends Path{} { src = Backup and dst = Database	and hops = 0->serBackupDatabase }
one sig pathDatabaseBackup extends Path{} { src = Database and dst = Backup and hops = 0->serDatabaseBackup }
one sig pathCoreClinical extends Path {} { src = Core and dst = Clinical and hops = 0->serCoreClinical }
one sig pathClinicalCore extends Path {} { src = Clinical and dst = Core and hops = 0->serClinicalCore }
one sig pathClinicalIoMT extends Path {} { src = Clinical and dst = IoMT and hops = 0->serClinicalIoMT }
one sig pathIoMTClinical extends Path {} { src = IoMT and dst = Clinical and hops = 0->serIoMTClinical }

one sig pathGuestEnterprise extends Path {} { src = Guest and dst = Enterprise and hops = 0->serGuestDMZ + 1->serDMZEnterprise }
one sig pathEnterpriseGuest extends Path {} { src = Enterprise and dst = Guest and hops = 0->serEnterpriseDMZ + 1->serDMZGuest }
one sig pathEnterpriseDatabase extends Path {} { src = Enterprise and dst = Database and hops = 0->serEnterpriseCore + 1->serCoreDatabase	}
one sig pathLabDatabase extends Path {} { src = Lab and dst = Database and hops = 0->serLabCore + 1->serCoreDatabase }
one sig pathDatabaseEnterprise extends Path {} { src = Database	and dst = Enterprise and hops = 0->serDatabaseCore + 1->serCoreEnterprise }
one sig pathDatabaseLab extends Path {} { src = Database and dst = Lab and hops = 0->serDatabaseCore + 1->serCoreLab }
one sig pathDatabaseClinical extends Path {} { src = Database and dst = Clinical and hops = 0->serDatabaseCore + 1->serCoreClinical }
one sig pathClinicalDatabase extends Path {} { src = Clinical and dst = Database and hops = 0->serClinicalCore + 1->serCoreDatabase }
one sig pathCoreIoMT extends Path {} { src = Core and dst = IoMT and hops = 0->serCoreClinical + 1->serClinicalIoMT }
one sig pathIoMTCore extends Path {} { src = IoMT and dst = Core and hops = 0->serIoMTClinical + 1->serClinicalCore }
