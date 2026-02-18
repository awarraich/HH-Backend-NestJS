import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Patient } from './entities/patient.entity';
import { PatientProfile } from './entities/patient-profile.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { AuditLogModule } from '../../common/services/audit/audit-log.module';
import { PatientsService } from './patients.service';
import { MedicationsModule } from './medications/medications.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Patient, PatientProfile]),
    AuthenticationModule,
    AuditLogModule,
    MedicationsModule,
  ],
  providers: [PatientsService],
  exports: [TypeOrmModule, PatientsService],
})
export class PatientsModule {}
