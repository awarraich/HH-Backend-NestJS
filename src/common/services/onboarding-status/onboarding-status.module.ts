import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OnboardingStatusService } from './onboarding-status.service';
import { OnboardingStatusController } from './onboarding-status.controller';
import { OrganizationsModule } from '../../../models/organizations/organizations.module';
import { Patient } from '../../../models/patients/entities/patient.entity';
import { Provider } from '../../../models/providers/entities/provider.entity';
import { Employee } from '../../../models/employees/entities/employee.entity';
import { Admin } from '../../../models/admins/entities/admin.entity';

@Module({
  imports: [
    forwardRef(() => OrganizationsModule),
    TypeOrmModule.forFeature([Patient, Provider, Employee, Admin]),
  ],
  controllers: [OnboardingStatusController],
  providers: [OnboardingStatusService],
  exports: [OnboardingStatusService],
})
export class OnboardingStatusModule {}

