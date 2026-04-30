import { forwardRef, Inject, Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { OfferLetterAssignment } from '../entities/offer-letter-assignment.entity';
import { JobApplication } from '../entities/job-application.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { EmployeeDocument } from '../../organizations/hr-files-setup/entities/employee-document.entity';
import { HrDocumentType } from '../../organizations/hr-files-setup/entities/hr-document-type.entity';
import { S3Service } from '../../../common/services/s3/s3.service';
import { OfferLetterAssignmentService } from './offer-letter-assignment.service';

/**
 * Auto-archives a fully-signed offer letter into the applicant's HR File as
 * an `EmployeeDocument` of type OFFER_LETTER. Triggered by the offer-letter
 * service at the moment an assignment's status flips to `completed`.
 *
 * Single responsibility: bake → upload → insert. No status mutation, no
 * email/notification side-effects, no signing-flow logic.
 *
 * Idempotency: derives a deterministic S3 key from the assignment id and
 * checks for an existing `EmployeeDocument` at that path before inserting.
 * A second call for the same completed assignment is a no-op.
 *
 * Pre-conditions checked here (not by the caller):
 *   - assignment must exist and be `completed`
 *   - the application must have an `applicant_user_id` (set when the
 *     applicant has actually authenticated and signed)
 *   - an `Employee` row must exist for that user in the assignment's org —
 *     if not, the doc can be backfilled later by re-calling `archive()`
 */
@Injectable()
export class OfferLetterArchiveService {
  private readonly logger = new Logger(OfferLetterArchiveService.name);

  constructor(
    @InjectRepository(OfferLetterAssignment)
    private readonly assignmentRepo: Repository<OfferLetterAssignment>,
    @InjectRepository(JobApplication)
    private readonly applicationRepo: Repository<JobApplication>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    @InjectRepository(EmployeeDocument)
    private readonly employeeDocumentRepo: Repository<EmployeeDocument>,
    @InjectRepository(HrDocumentType)
    private readonly hrDocumentTypeRepo: Repository<HrDocumentType>,
    // Bidirectional dep: OfferLetterAssignmentService also injects this
    // service (via forwardRef) so its completion hook can fire archive().
    // Both sides need forwardRef to break the cycle at construction time.
    @Inject(forwardRef(() => OfferLetterAssignmentService))
    private readonly offerLetterService: OfferLetterAssignmentService,
    private readonly s3Service: S3Service,
  ) {}

  /**
   * Archive a completed offer-letter assignment to the applicant's HR File.
   * Returns the resulting EmployeeDocument, or `null` if a precondition
   * isn't met (assignment missing, applicant not yet a user, employee row
   * not yet created, OFFER_LETTER doc type missing). Never throws on
   * pre-conditions — only on infrastructure errors (S3, DB writes).
   */
  async archive(assignmentId: string): Promise<EmployeeDocument | null> {
    const assignment = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
    });
    if (!assignment || assignment.status !== 'completed') {
      this.logger.log(
        `archive: assignment ${assignmentId} not found or not completed — skip`,
      );
      return null;
    }

    const application = await this.applicationRepo.findOne({
      where: { id: assignment.job_application_id },
    });
    if (!application?.applicant_user_id) {
      this.logger.log(
        `archive: assignment ${assignmentId} has no applicant_user_id yet — skip (will retry after hire)`,
      );
      return null;
    }

    const employee = await this.employeeRepo.findOne({
      where: {
        user_id: application.applicant_user_id,
        organization_id: assignment.organization_id,
        deleted_at: IsNull(),
      },
    });
    if (!employee) {
      this.logger.log(
        `archive: no Employee row yet for user ${application.applicant_user_id} in org ${assignment.organization_id} — skip (will retry after hire)`,
      );
      return null;
    }

    const docType = await this.resolveOfferLetterType(assignment.organization_id);
    if (!docType) {
      this.logger.warn(
        `archive: OFFER_LETTER document type not found for org ${assignment.organization_id}. Run the org seed.`,
      );
      return null;
    }

    // Deterministic key per assignment — second call writes to the same
    // S3 object and finds the existing DB row, so the operation is idempotent
    // without needing a unique-index migration.
    const s3Key = this.buildS3Key(assignment.organization_id, employee.id, assignmentId);

    const existing = await this.employeeDocumentRepo.findOne({
      where: { file_path: s3Key, deleted_at: IsNull() },
    });
    if (existing) return existing;

    const baked = await this.offerLetterService.bakeSignedPdf(assignmentId);
    await this.s3Service.putObject({
      key: s3Key,
      body: baked.buffer,
      contentType: baked.contentType,
    });

    const created = this.employeeDocumentRepo.create({
      organization_id: assignment.organization_id,
      employee_id: employee.id,
      document_type_id: docType.id,
      file_name: 'Signed Offer Letter.pdf',
      file_path: s3Key,
      file_size_bytes: baked.buffer.length,
      mime_type: baked.contentType,
      uploaded_by: assignment.created_by,
      // System-generated PDF whose canonical content lives in
      // offer_letter_field_values. We don't run text extraction on it —
      // HR views/downloads rather than searching it.
      extraction_status: 'completed',
      extracted_text: null,
    });

    return this.employeeDocumentRepo.save(created);
  }

  /**
   * Resolve the OFFER_LETTER document type for an organization. Prefers the
   * org's own seeded row (every org gets one via the bootstrap seed), falls
   * back to a global definition if any code seeded one without an org id.
   */
  private async resolveOfferLetterType(
    organizationId: string,
  ): Promise<HrDocumentType | null> {
    const orgScoped = await this.hrDocumentTypeRepo.findOne({
      where: { code: 'OFFER_LETTER', organization_id: organizationId },
    });
    if (orgScoped) return orgScoped;
    const global = await this.hrDocumentTypeRepo
      .createQueryBuilder('t')
      .where('t.code = :code', { code: 'OFFER_LETTER' })
      .andWhere('t.organization_id IS NULL')
      .getOne();
    return global;
  }

  /**
   * Stable per-assignment object key. Including the assignment id makes it
   * deterministic (so re-runs find the same row); including the employee
   * id keeps offer letters partitioned per-employee in S3 listings.
   */
  private buildS3Key(orgId: string, employeeId: string, assignmentId: string): string {
    return `organizations/${orgId}/employees/${employeeId}/offer-letters/${assignmentId}.pdf`;
  }
}
