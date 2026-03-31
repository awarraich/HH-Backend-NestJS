import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DocumentFieldValue } from './entities/document-field-value.entity';
import { CompetencyTemplate } from '../organizations/document-workflow/entities/competency-template.entity';
import { Employee } from '../employees/entities/employee.entity';
import { User } from '../../authentication/entities/user.entity';
import { ExternalDocumentService } from './services/external-document.service';
import { ExternalDocumentController } from './controllers/external-document.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([DocumentFieldValue, CompetencyTemplate, Employee, User]),
  ],
  controllers: [ExternalDocumentController],
  providers: [ExternalDocumentService],
  exports: [ExternalDocumentService],
})
export class ExternalDocumentsModule {}
