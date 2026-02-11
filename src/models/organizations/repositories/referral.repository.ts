import { Injectable } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { Referral } from '../entities/referral.entity';

export interface ReferralListFilters {
  status?: string;
  organization_type_id?: number;
  search?: string;
  page?: number;
  limit?: number;
  assigned_to_me?: boolean;
}

@Injectable()
export class ReferralRepository extends Repository<Referral> {
  constructor(private dataSource: DataSource) {
    super(Referral, dataSource.createEntityManager());
  }

  async findBySent(
    organizationId: string,
    filters: ReferralListFilters,
  ): Promise<{ data: Referral[]; total: number }> {
    const { status, organization_type_id, search, page = 1, limit = 20 } = filters;
    const qb = this.createQueryBuilder('referral')
      .leftJoinAndSelect('referral.patient', 'patient')
      .leftJoinAndSelect('patient.profile', 'patientProfile')
      .leftJoinAndSelect('referral.sendingOrganization', 'sendingOrg')
      .leftJoinAndSelect('sendingOrg.profile', 'sendingOrgProfile')
      .leftJoinAndSelect('referral.organizationType', 'orgType')
      .leftJoinAndSelect('referral.referralOrganizations', 'ro')
      .leftJoinAndSelect('ro.organization', 'roOrg')
      .leftJoinAndSelect('roOrg.profile', 'roOrgProfile')
      .leftJoinAndSelect('referral.referralDocuments', 'referralDocuments')
      .where('referral.sending_organization_id = :organizationId', { organizationId });

    if (status) {
      qb.andWhere('referral.status = :status', { status });
    }
    if (organization_type_id !== undefined) {
      qb.andWhere('referral.organization_type_id = :organization_type_id', { organization_type_id });
    }
    if (search && search.trim()) {
      qb.andWhere(
        '(referral.public_id ILIKE :search OR patientProfile.name ILIKE :searchPattern)',
        { search: `%${search.trim()}%`, searchPattern: `%${search.trim()}%` },
      );
    }

    const [data, total] = await qb
      .orderBy('referral.created_at', 'DESC')
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();
    return { data, total };
  }

  async findByReceived(
    organizationId: string,
    filters: ReferralListFilters,
  ): Promise<{ data: Referral[]; total: number }> {
    const { status, organization_type_id, search, assigned_to_me, page = 1, limit = 20 } = filters;
    const qb = this.createQueryBuilder('referral')
      .innerJoin('referral.referralOrganizations', 'ro', 'ro.organization_id = :organizationId', {
        organizationId,
      })
      .leftJoinAndSelect('referral.patient', 'patient')
      .leftJoinAndSelect('patient.profile', 'patientProfile')
      .leftJoinAndSelect('referral.sendingOrganization', 'sendingOrg')
      .leftJoinAndSelect('sendingOrg.profile', 'sendingOrgProfile')
      .leftJoinAndSelect('referral.organizationType', 'orgType')
      .leftJoinAndSelect('referral.referralOrganizations', 'roAll')
      .leftJoinAndSelect('roAll.organization', 'roOrg')
      .leftJoinAndSelect('roOrg.profile', 'roOrgProfile')
      .leftJoinAndSelect('referral.referralDocuments', 'referralDocuments')
      .where('1=1');

    if (status) {
      qb.andWhere('referral.status = :status', { status });
    }
    if (assigned_to_me === true) {
      qb.andWhere('referral.selected_organization_id = :organizationId', { organizationId });
    }
    if (organization_type_id !== undefined) {
      qb.andWhere('referral.organization_type_id = :organization_type_id', { organization_type_id });
    }
    if (search && search.trim()) {
      qb.andWhere(
        '(referral.public_id ILIKE :search OR patientProfile.name ILIKE :searchPattern)',
        { search: `%${search.trim()}%`, searchPattern: `%${search.trim()}%` },
      );
    }

    const [data, total] = await qb
      .orderBy('referral.created_at', 'DESC')
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();
    return { data, total };
  }

  async findByIdWithRelations(referralId: string): Promise<Referral | null> {
    return this.findOne({
      where: { id: referralId },
      relations: [
        'patient',
        'patient.profile',
        'sendingOrganization',
        'sendingOrganization.profile',
        'selectedOrganization',
        'selectedOrganization.profile',
        'organizationType',
        'referralOrganizations',
        'referralOrganizations.organization',
        'referralOrganizations.organization.profile',
        'referralDocuments',
      ],
    });
  }

  async getNextPublicId(): Promise<string> {
    const result = await this.createQueryBuilder('referral')
      .select("COALESCE(MAX(CAST(REPLACE(referral.public_id, 'REF-', '') AS INTEGER)), 0) + 1", 'next')
      .where("referral.public_id LIKE 'REF-%'")
      .getRawOne<{ next: string }>();
    const num = result?.next ? parseInt(result.next, 10) : 1;
    return `REF-${String(num).padStart(3, '0')}`;
  }
}
