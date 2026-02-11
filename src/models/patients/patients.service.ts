import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Patient } from './entities/patient.entity';
import { PatientProfile } from './entities/patient-profile.entity';
import { AuditLogService } from '../../common/services/audit/audit-log.service';

export interface CreatePatientForReferralInput {
  name: string;
  date_of_birth?: string;
  address?: string;
  primary_insurance_provider?: string;
}

export interface AuditContext {
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class PatientsService {
  constructor(
    @InjectRepository(Patient)
    private patientRepository: Repository<Patient>,
    @InjectRepository(PatientProfile)
    private patientProfileRepository: Repository<PatientProfile>,
    private auditLogService: AuditLogService,
  ) {}

  async createForReferral(
    organizationId: string,
    input: CreatePatientForReferralInput,
    auditContext?: AuditContext,
  ): Promise<string> {
    const patient = this.patientRepository.create({
      user_id: null,
      organization_id: organizationId,
    });
    const savedPatient = await this.patientRepository.save(patient);
    const profile = this.patientProfileRepository.create({
      patient_id: savedPatient.id,
      name: input.name,
      address: input.address ?? null,
      primary_insurance_provider: input.primary_insurance_provider ?? null,
      date_of_birth: input.date_of_birth ? new Date(input.date_of_birth) : null,
    } as Partial<PatientProfile>);
    await this.patientProfileRepository.save(profile);
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'CREATE',
          resourceType: 'PATIENT',
          resourceId: savedPatient.id,
          description: 'Patient created for referral',
          metadata: { organization_id: organizationId },
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
        });
      } catch {
        // ignore audit failure
      }
    }
    return savedPatient.id;
  }
}
