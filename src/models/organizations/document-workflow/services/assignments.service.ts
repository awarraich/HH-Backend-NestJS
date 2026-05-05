import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { CompetencyAssignment } from '../entities/competency-assignment.entity';
import { DocumentTemplateUserAssignment } from '../entities/document-template-user-assignment.entity';
import { CreateAssignmentDto } from '../dto/create-assignment.dto';
import { FillAssignmentDto } from '../dto/fill-assignment.dto';
import { TemplatesService } from './templates.service';

@Injectable()
export class AssignmentsService {
  constructor(
    @InjectRepository(CompetencyAssignment)
    private readonly repo: Repository<CompetencyAssignment>,
    @InjectRepository(DocumentTemplateUserAssignment)
    private readonly templateUserRepo: Repository<DocumentTemplateUserAssignment>,
    private readonly templatesService: TemplatesService,
  ) {}

  private mapAssignment(a: CompetencyAssignment) {
    if (!a) return a;
    const result = { ...a };
    if (result.template_snapshot?.pdf_file_key) {
      result.template_snapshot = {
        ...result.template_snapshot,
        pdfUrl: this.templatesService.buildPdfUrl(a.organization_id, result.template_snapshot.id)
      };
    }
    return result;
  }

  async findAll(orgId: string, filters?: { status?: string; supervisorId?: string }) {
    const qb = this.repo
      .createQueryBuilder('a')
      .where('a.organization_id = :orgId', { orgId })
      .orderBy('a.created_at', 'DESC');

    if (filters?.status) {
      qb.andWhere('a.status = :status', { status: filters.status });
    }
    if (filters?.supervisorId) {
      qb.andWhere('a.supervisor_id = :sid', { sid: filters.supervisorId });
    }

    const assignments = await qb.getMany();
    return assignments.map(a => this.mapAssignment(a));
  }

  async findOne(orgId: string, id: string) {
    const a = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!a) throw new NotFoundException('Assignment not found');
    return this.mapAssignment(a);
  }

  async create(orgId: string, dto: CreateAssignmentDto, userId: string) {
    const template = await this.templatesService.findOne(orgId, dto.templateId);

    const snapshot = {
      id: template.id,
      name: template.name,
      description: template.description,
      roles: template.roles,
      document_fields: template.document_fields,
      pdf_file_key: template.pdf_file_key,
    };

    const saved = await this.repo.save(
      this.repo.create({
        organization_id: orgId,
        template_id: template.id,
        template_snapshot: snapshot,
        name: template.name || 'Untitled',
        supervisor_id: dto.supervisorId,
        status: 'sent',
        created_by: userId,
      }),
    );
    return this.mapAssignment(saved);
  }

  async fill(orgId: string, id: string, dto: FillAssignmentDto) {
    const a = await this.findOne(orgId, id);
    a.field_values = { ...a.field_values, ...dto.fieldValues };
    if (a.status === 'sent') a.status = 'in_progress';
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  async submit(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    a.status = 'completed';
    a.completed_at = new Date();
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  async void(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    a.status = 'voided';
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  async delete(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    await this.repo.remove(a);
  }

  async getForSupervisor(supervisorId: string) {
    const assignments = await this.repo.find({
      where: { supervisor_id: supervisorId, status: In(['sent', 'in_progress', 'completed']) },
      order: { created_at: 'DESC' },
    });
    return assignments.map(a => this.mapAssignment(a));
  }

  /**
   * List competency assignments where the given user is involved in any
   * template role for this org. The link is indirect: an "employee" is
   * tied to templates via `document_template_user_assignments`, not
   * directly to a `competency_assignments` row. We therefore:
   *   1. find every template the user is assigned to,
   *   2. AND every template where they're the supervisor on an assignment,
   *   3. then fetch competency_assignments matching either path within the
   *      org, deduped by id.
   * This powers the "Document Workflows" panel on the employee HR File.
   */
  async getForEmployee(orgId: string | null | undefined, userId: string) {
    // Templates this user has any role on (employee, supervisor, etc.).
    const userTemplateRows = await this.templateUserRepo
      .createQueryBuilder('ua')
      .select('DISTINCT ua.template_id', 'template_id')
      .where('ua.user_id = :userId', { userId })
      .getRawMany<{ template_id: string }>();
    const templateIds = userTemplateRows.map((r) => r.template_id);

    const qb = this.repo
      .createQueryBuilder('a')
      .orderBy('a.created_at', 'DESC');

    if (orgId) {
      qb.where('a.organization_id = :orgId', { orgId });
    }
    if (templateIds.length > 0) {
      qb.andWhere(
        '(a.supervisor_id = :userId OR a.template_id IN (:...templateIds))',
        { userId, templateIds },
      );
    } else {
      qb.andWhere('a.supervisor_id = :userId', { userId });
    }

    const assignments = await qb.getMany();
    return assignments.map((a) => this.mapAssignment(a));
  }

  async employeeSign(id: string, signature: string) {
    const a = await this.repo.findOne({ where: { id } });
    if (!a) throw new NotFoundException('Assignment not found');
    a.employee_signature = signature;
    a.employee_signed_at = new Date();
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }
}
