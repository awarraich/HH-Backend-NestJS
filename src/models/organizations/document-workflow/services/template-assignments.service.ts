import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { DocumentTemplateUserAssignment } from '../entities/document-template-user-assignment.entity';
import { CompetencyTemplate } from '../entities/competency-template.entity';
import { DocumentWorkflowRole } from '../entities/document-workflow-role.entity';
import { AssignTemplateUsersDto } from '../dto/assign-template-user.dto';

@Injectable()
export class TemplateAssignmentsService {
  constructor(
    @InjectRepository(DocumentTemplateUserAssignment)
    private readonly assignmentRepo: Repository<DocumentTemplateUserAssignment>,
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(DocumentWorkflowRole)
    private readonly roleRepo: Repository<DocumentWorkflowRole>,
  ) {}

  /**
   * List all user assignments for a template.
   */
  async findAllForTemplate(orgId: string, templateId: string) {
    const template = await this.templateRepo.findOne({
      where: { id: templateId, organization_id: orgId },
    });
    if (!template) throw new NotFoundException('Template not found');

    return this.assignmentRepo.find({
      where: { template_id: templateId },
      relations: ['role'],
      order: { created_at: 'DESC' },
    });
  }

  /**
   * Assign users to a template with specific roles.
   * Validates that:
   * - Template exists in the org
   * - Each role exists (default or org-specific)
   * - Each role is actually used in the template's document_fields
   */
  async assign(
    orgId: string,
    templateId: string,
    dto: AssignTemplateUsersDto,
    assignedBy: string,
  ) {
    const template = await this.templateRepo.findOne({
      where: { id: templateId, organization_id: orgId },
    });
    if (!template) throw new NotFoundException('Template not found');

    // Collect unique role IDs from the request
    const roleIds = [...new Set(dto.assignments.map((a) => a.roleId))];

    // Validate all roles exist (default or org-specific)
    const roles = await this.roleRepo
      .createQueryBuilder('r')
      .where('r.id IN (:...roleIds)', { roleIds })
      .andWhere('(r.organization_id = :orgId OR r.is_default = true)', { orgId })
      .getMany();

    if (roles.length !== roleIds.length) {
      throw new BadRequestException('One or more role IDs are invalid');
    }

    // Validate each role is actually used in the template's document_fields
    const templateRoleIds = new Set(
      template.document_fields
        .map((f: Record<string, any>) => f.assignedRoleId)
        .filter(Boolean),
    );

    const invalidRoles = roleIds.filter((id) => !templateRoleIds.has(id));
    if (invalidRoles.length > 0) {
      const invalidNames = roles
        .filter((r) => invalidRoles.includes(r.id))
        .map((r) => r.name);
      throw new BadRequestException(
        `These roles are not assigned to any field in this template: ${invalidNames.join(', ')}`,
      );
    }

    // Upsert assignments (skip duplicates)
    const saved: DocumentTemplateUserAssignment[] = [];
    for (const item of dto.assignments) {
      const existing = await this.assignmentRepo.findOne({
        where: {
          template_id: templateId,
          user_id: item.userId,
          role_id: item.roleId,
        },
      });

      if (!existing) {
        saved.push(
          await this.assignmentRepo.save(
            this.assignmentRepo.create({
              template_id: templateId,
              user_id: item.userId,
              role_id: item.roleId,
              assigned_by: assignedBy,
            }),
          ),
        );
      } else {
        saved.push(existing);
      }
    }

    return saved;
  }

  /**
   * Remove a specific assignment.
   */
  async unassign(orgId: string, templateId: string, assignmentId: string) {
    const template = await this.templateRepo.findOne({
      where: { id: templateId, organization_id: orgId },
    });
    if (!template) throw new NotFoundException('Template not found');

    const assignment = await this.assignmentRepo.findOne({
      where: { id: assignmentId, template_id: templateId },
    });
    if (!assignment) throw new NotFoundException('Assignment not found');

    await this.assignmentRepo.remove(assignment);
  }
}
