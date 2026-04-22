import { IsString, IsOptional, IsArray, IsIn } from 'class-validator';

export class CreateTemplateDto {
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  documentFields?: Record<string, any>[];

  @IsOptional()
  @IsArray()
  roles?: Record<string, any>[];

  /**
   * Which tab of Document Workflow this template belongs to. `'document'`
   * (default) is the original competency / signable-document use case;
   * `'applicant_form'` is a PDF applicants fill when applying for a job.
   */
  @IsOptional()
  @IsIn(['document', 'applicant_form'])
  purpose?: 'document' | 'applicant_form';
}
