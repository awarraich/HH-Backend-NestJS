import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, In } from 'typeorm';
import { Referral } from '../entities/referral.entity';
import { ReferralOrganization } from '../entities/referral-organization.entity';
import { ReferralMessage } from '../entities/referral-message.entity';
import { ReferralDocument } from '../entities/referral-document.entity';
import { Organization } from '../entities/organization.entity';
import { OrganizationType } from '../entities/organization-type.entity';
import { Patient } from '../../patients/entities/patient.entity';
import { ReferralRepository } from '../repositories/referral.repository';
import { ReferralSerializer } from '../serializers/referral.serializer';
import { CreateReferralDto } from '../dto/create-referral.dto';
import { QueryReferralDto } from '../dto/query-referral.dto';
import { UpdateReferralResponseDto } from '../dto/update-referral-response.dto';
import { AssignReferralDto } from '../dto/assign-referral.dto';
import { PatientsService } from '../../patients/patients.service';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';
import type { ReferralListFilters } from '../repositories/referral.repository';
import { TemplatesService } from '../document-workflow/services/templates.service';

@Injectable()
export class ReferralsService {
  private readonly serializer = new ReferralSerializer();

  constructor(
    private referralRepository: ReferralRepository,
    private templatesService: TemplatesService,
    @InjectRepository(ReferralOrganization)
    private referralOrganizationRepository: Repository<ReferralOrganization>,
    @InjectRepository(ReferralMessage)
    private referralMessageRepository: Repository<ReferralMessage>,
    @InjectRepository(ReferralDocument)
    private referralDocumentRepository: Repository<ReferralDocument>,
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(OrganizationType)
    private organizationTypeRepository: Repository<OrganizationType>,
    @InjectRepository(Patient)
    private patientRepository: Repository<Patient>,
    private dataSource: DataSource,
    private patientsService: PatientsService,
    private auditLogService: AuditLogService,
  ) {}

  /**
   * Batch-load template PDFs for referrals that have document_template_ids
   * and append them to each serialized referral's documents array.
   */
  private async appendTemplateDocs(
    serializedList: any[],
    rawReferrals: Referral[],
  ): Promise<void> {
    const allIds = new Set<string>();
    for (const r of rawReferrals) {
      if (r.document_template_ids?.length) {
        r.document_template_ids.forEach((id) => allIds.add(id));
      }
    }
    if (allIds.size === 0) return;

    const templates = await this.templatesService.findByIdsWithValues([...allIds]);
    const templateMap = new Map(templates.map((t: any) => [t.id, t]));

    for (let i = 0; i < rawReferrals.length; i++) {
      const ids = rawReferrals[i].document_template_ids;
      if (!ids?.length) continue;

      const templateDocs = ids
        .map((id) => templateMap.get(id))
        .filter(Boolean)
        .map((t: any) => ({
          id: t.id,
          file_name: t.name,
          file_url: t.pdfUrl,
          created_at: t.created_at,
          type: 'template',
          document_fields: t.document_fields,
        }));

      serializedList[i].documents = [
        ...(serializedList[i].documents || []),
        ...templateDocs,
      ];
    }
  }

  async create(
    organizationId: string,
    userId: string,
    dto: CreateReferralDto,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    if (dto.patient_id && dto.patient) {
      throw new BadRequestException('Provide either patient_id or patient, not both');
    }
    if (!dto.patient_id && !dto.patient) {
      throw new BadRequestException('Provide either patient_id or patient');
    }

    let patientId: string;
    if (dto.patient_id) {
      const patient = await this.patientRepository.findOne({ where: { id: dto.patient_id } });
      if (!patient) throw new NotFoundException('Patient not found');
      patientId = dto.patient_id;
    } else {
      patientId = await this.patientsService.createForReferral(
        organizationId,
        {
          name: dto.patient!.name,
          date_of_birth: dto.patient!.date_of_birth,
          address: dto.patient!.address,
          primary_insurance_provider: dto.patient!.primary_insurance_provider,
        },
        { userId, ipAddress, userAgent },
      );
    }

    const orgType = await this.organizationTypeRepository.findOne({
      where: { id: dto.organization_type_id },
    });
    if (!orgType) throw new NotFoundException('Organization type not found');

    const sendingOrg = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!sendingOrg) throw new NotFoundException('Sending organization not found');

    const receivingIds = [...new Set(dto.receiving_organization_ids)];
    if (receivingIds.length !== dto.receiving_organization_ids.length) {
      throw new BadRequestException('Duplicate receiving organizations');
    }
    const existingOrgs = await this.organizationRepository.find({
      where: { id: In(receivingIds) },
    });
    if (existingOrgs.length !== receivingIds.length) {
      throw new BadRequestException('One or more receiving organizations not found');
    }
    if (receivingIds.includes(organizationId)) {
      throw new BadRequestException('Cannot send referral to your own organization');
    }

    const publicId = await this.referralRepository.getNextPublicId();

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    try {
      const referral = this.referralRepository.create({
        public_id: publicId,
        organization_type_id: dto.organization_type_id,
        urgency: dto.urgency,
        patient_id: patientId,
        sending_organization_id: organizationId,
        insurance_provider: dto.insurance_provider ?? null,
        estimated_cost: dto.estimated_cost ?? null,
        notes: dto.notes,
        level_of_care: dto.level_of_care ?? null,
        document_template_ids: dto.document_template_ids?.length ? dto.document_template_ids : null,
      });
      const savedReferral = await queryRunner.manager.save(Referral, referral);

      for (const orgId of receivingIds) {
        const ro = this.referralOrganizationRepository.create({
          referral_id: savedReferral.id,
          organization_id: orgId,
          response_status: 'pending',
        });
        await queryRunner.manager.save(ReferralOrganization, ro);
      }

      const systemMsg = this.referralMessageRepository.create({
        referral_id: savedReferral.id,
        message: `Referral sent to ${receivingIds.length} organization(s).`,
        is_system: true,
      });
      await queryRunner.manager.save(ReferralMessage, systemMsg);

      if (dto.documents?.length) {
        for (const doc of dto.documents) {
          const refDoc = this.referralDocumentRepository.create({
            referral_id: savedReferral.id,
            file_name: doc.file_name,
            file_url: doc.file_url,
          });
          await queryRunner.manager.save(ReferralDocument, refDoc);
        }
      }

      await queryRunner.commitTransaction();
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'REFERRAL',
          resourceId: savedReferral.id,
          description: 'Referral created',
          metadata: {
            public_id: publicId,
            sending_organization_id: organizationId,
            patient_id: patientId,
            receiver_count: receivingIds.length,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch {
        // ignore
      }
      const loaded = await this.referralRepository.findByIdWithRelations(savedReferral.id);
      const serialized = this.serializer.serialize(loaded!);
      await this.appendTemplateDocs([serialized], [loaded!]);
      return serialized;
    } catch (e) {
      await queryRunner.rollbackTransaction();
      throw e;
    } finally {
      await queryRunner.release();
    }
  }

  async findAll(
    organizationId: string,
    queryDto: QueryReferralDto,
    _userId?: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<{ data: unknown[]; total: number; page: number; limit: number }> {
    const filters: ReferralListFilters = {
      status: queryDto.status,
      organization_type_id: queryDto.organization_type_id,
      search: queryDto.search,
      page: queryDto.page ?? 1,
      limit: queryDto.limit ?? 20,
      assigned_to_me: queryDto.assigned_to_me,
    };
    const { data, total } =
      queryDto.scope === 'sent'
        ? await this.referralRepository.findBySent(organizationId, filters)
        : await this.referralRepository.findByReceived(organizationId, filters);

    const serialized = this.serializer.serializeMany(data);
    await this.appendTemplateDocs(serialized, data);

    return {
      data: serialized,
      total,
      page: filters.page ?? 1,
      limit: filters.limit ?? 20,
    };
  }

  async findOne(
    organizationId: string,
    referralId: string,
    _userId?: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<unknown> {
    const referral = await this.referralRepository.findByIdWithRelations(referralId);
    if (!referral) throw new NotFoundException('Referral not found');
    const isSender = referral.sending_organization_id === organizationId;
    const isReceiver = referral.referralOrganizations?.some(
      (ro) => ro.organization_id === organizationId,
    );
    if (!isSender && !isReceiver) {
      throw new ForbiddenException('You do not have access to this referral');
    }

    const serialized = this.serializer.serialize(referral);
    await this.appendTemplateDocs([serialized], [referral]);
    return serialized;
  }

  async updateResponse(
    organizationId: string,
    referralId: string,
    dto: UpdateReferralResponseDto,
    _userId?: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<unknown> {
    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
      relations: ['referralOrganizations'],
    });
    if (!referral) throw new NotFoundException('Referral not found');
    const ro = referral.referralOrganizations?.find((r) => r.organization_id === organizationId);
    if (!ro) throw new ForbiddenException('You do not have access to this referral');
    ro.response_status = dto.response_status;
    ro.response_date = new Date();
    ro.proposed_terms = dto.proposed_terms ?? ro.proposed_terms;
    ro.notes = dto.notes ?? ro.notes;
    await this.referralOrganizationRepository.save(ro);
    const updated = await this.referralRepository.findByIdWithRelations(referralId);
    return this.serializer.serialize(updated!);
  }

  async assignToOrganization(
    organizationId: string,
    referralId: string,
    dto: AssignReferralDto,
    _userId?: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<unknown> {
    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
      relations: ['referralOrganizations'],
    });
    if (!referral) throw new NotFoundException('Referral not found');
    if (referral.sending_organization_id !== organizationId) {
      throw new ForbiddenException('Only the sending organization can assign the referral');
    }
    const ro = referral.referralOrganizations?.find(
      (r) => r.organization_id === dto.organization_id,
    );
    if (!ro) throw new BadRequestException('Organization is not a receiver of this referral');
    referral.selected_organization_id = dto.organization_id;
    ro.response_status = 'assigned';
    await this.referralOrganizationRepository.save(ro);
    await this.referralRepository.save(referral);
    const updated = await this.referralRepository.findByIdWithRelations(referralId);
    return this.serializer.serialize(updated!);
  }

  async getResponses(
    organizationId: string,
    referralId: string,
    _userId?: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<unknown> {
    const referral = await this.referralRepository.findByIdWithRelations(referralId);
    if (!referral) throw new NotFoundException('Referral not found');
    if (referral.sending_organization_id !== organizationId) {
      throw new ForbiddenException('Only the sending organization can view responses');
    }
    return (
      referral.referralOrganizations?.map((ro) => ({
        org_id: ro.organization_id,
        org_name: ro.organization?.organization_name ?? null,
        response_status: ro.response_status,
        response_date: ro.response_date,
        proposed_terms: ro.proposed_terms,
        notes: ro.notes,
      })) ?? []
    );
  }
}
