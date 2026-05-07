import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DocumentFieldValue } from './entities/document-field-value.entity';
import { CompetencyTemplate } from '../organizations/document-workflow/entities/competency-template.entity';
import { CompetencyTemplateVersion } from '../organizations/document-workflow/entities/competency-template-version.entity';
import { DocumentTemplateUserAssignment } from '../organizations/document-workflow/entities/document-template-user-assignment.entity';
import { DocumentAssignmentEvent } from '../organizations/document-workflow/entities/document-assignment-event.entity';
import { User } from '../../authentication/entities/user.entity';
import { Employee } from '../employees/entities/employee.entity';
import { OrganizationStaff } from '../organizations/staff-management/entities/organization-staff.entity';
import { ExternalDocumentService } from './services/external-document.service';
import { ExternalDocumentController } from './controllers/external-document.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      DocumentFieldValue,
      CompetencyTemplate,
      CompetencyTemplateVersion,
      DocumentTemplateUserAssignment,
      DocumentAssignmentEvent,
      User,
      Employee,
      OrganizationStaff,
    ]),
  ],
  controllers: [ExternalDocumentController],
  providers: [ExternalDocumentService],
  exports: [ExternalDocumentService],
})
export class ExternalDocumentsModule {}
