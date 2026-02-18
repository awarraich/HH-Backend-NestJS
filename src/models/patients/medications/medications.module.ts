import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PatientMedication } from './entities/patient-medication.entity';
import { PatientMedicationTimeSlot } from './entities/patient-medication-time-slot.entity';
import { MedicationAdministration } from './entities/medication-administration.entity';
import { MedicationsController } from './medications.controller';
import { MedicationsService } from './medications.service';
import { AuthenticationModule } from '../../../authentication/auth.module';
import { AuditLogModule } from '../../../common/services/audit/audit-log.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      PatientMedication,
      PatientMedicationTimeSlot,
      MedicationAdministration,
    ]),
    AuthenticationModule,
    AuditLogModule,
  ],
  controllers: [MedicationsController],
  providers: [MedicationsService],
  exports: [MedicationsService],
})
export class MedicationsModule {}
