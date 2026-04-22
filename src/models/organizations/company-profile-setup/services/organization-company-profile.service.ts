import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  HttpException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomUUID } from 'crypto';
import { Organization } from '../../entities/organization.entity';
import { OrganizationCompanyProfile } from '../entities/organization-company-profile.entity';
import type {
  GalleryItemStored,
  VideoItemStored,
} from '../entities/organization-company-profile.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CompanyProfileStorageService } from './company-profile-storage.service';
import { S3Service } from '../../../../common/services/s3/s3.service';
import { UpdateOrganizationCompanyProfileDto } from '../dto/update-organization-company-profile.dto';

/** Amenity item returned to frontend (snake_case for API). */
export type AmenityItemResponse = {
  name: string;
  image_url?: string | null;
  price?: string | null;
};

/** Shape returned to frontend: gallery/videos have url for display (media endpoint or external). */
export type CompanyProfileResponse = {
  id: string;
  organization_id: string;
  company_name: string | null;
  logo: string | null;
  cover_image: string | null;
  cover_images: string[];
  organization_type: string | null;
  description: string | null;
  phone: string | null;
  email: string | null;
  fax: string | null;
  website: string | null;
  address_line_1: string | null;
  address_line_2: string | null;
  city: string | null;
  state: string | null;
  zip_code: string | null;
  country: string | null;
  business_hours: Record<string, { open: string; close: string; closed: boolean }> | null;
  service_area: string[] | null;
  coverage_radius: string | null;
  selected_services: string[] | null;
  licenses: string[] | null;
  certifications: string[] | null;
  gallery: Array<{ id: string; url: string; caption: string; category: string }>;
  videos: Array<{
    id: string;
    url: string;
    title: string;
    thumbnail?: string;
    description?: string;
    duration?: string;
    category?: string;
  }>;
  packages: Array<{
    id: string;
    name: string;
    description: string;
    price: string;
    features?: string[];
  }>;
  specialty_services: string[] | null;
  accepted_insurance: string[] | null;
  amenities: AmenityItemResponse[] | null;
  room_types: string[] | null;
  equipment_catalog: string[] | null;
  transport_types: string[] | null;
  availability_status: string | null;
  rating: number | null;
  review_count: number | null;
  reviews: Array<{
    id: string;
    author: string;
    rating: number;
    text: string;
    date: string;
    reply?: string;
    replied_at?: string;
  }>;
  created_at: Date;
  updated_at: Date;
};

@Injectable()
export class OrganizationCompanyProfileService {
  private readonly logger = new Logger(OrganizationCompanyProfileService.name);

  constructor(
    @InjectRepository(OrganizationCompanyProfile)
    private readonly profileRepository: Repository<OrganizationCompanyProfile>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    private readonly organizationRoleService: OrganizationRoleService,
    private readonly storageService: CompanyProfileStorageService,
    private readonly s3Service: S3Service,
  ) {}

  async presignGalleryUpload(
    organizationId: string,
    filename: string,
    contentType: string,
    userId: string,
  ): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    await this.ensureAccess(organizationId, userId);
    return this.storageService.presignGalleryUpload(organizationId, filename, contentType);
  }

  async presignVideoUpload(
    organizationId: string,
    filename: string,
    contentType: string,
    userId: string,
  ): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    await this.ensureAccess(organizationId, userId);
    return this.storageService.presignVideoUpload(organizationId, filename, contentType);
  }

  private async ensureAccess(organizationId: string, userId: string): Promise<void> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (!canAccess) {
      throw new ForbiddenException(
        'You do not have permission to manage company profile in this organization.',
      );
    }
    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
  }

  /** Build media URL for a stored gallery or video item (path only; host added by client). */
  buildMediaPath(organizationId: string, type: 'gallery' | 'video', fileId: string): string {
    return `/v1/api/organizations/${organizationId}/company-profile/media/${type}/${fileId}`;
  }

  /** Same but for public view (no auth). */
  buildPublicMediaPath(organizationId: string, type: 'gallery' | 'video', fileId: string): string {
    return `/v1/api/organizations/${organizationId}/company-profile/public-media/${type}/${fileId}`;
  }

  /** Rewrite stored media path to public-media path so public response uses same strategy as gallery/videos (works local and live). */
  private toPublicMediaPath(path: string | null | undefined): string | null {
    if (path == null || typeof path !== 'string') return path ?? null;
    if (path.includes('/company-profile/media/')) {
      return path.replace(/\/company-profile\/media\//g, '/company-profile/public-media/');
    }
    return path;
  }

  private mapProfileToResponse(
    profile: OrganizationCompanyProfile,
    organizationId: string,
    usePublicMedia = false,
  ): CompanyProfileResponse {
    const mediaPath = usePublicMedia
      ? this.buildPublicMediaPath.bind(this)
      : this.buildMediaPath.bind(this);
    const galleryRaw = Array.isArray(profile.gallery) ? profile.gallery : [];
    const gallery = galleryRaw.map((item: GalleryItemStored) => ({
      id: item?.id ?? '',
      url: item?.file_path ? mediaPath(organizationId, 'gallery', item.id) : (item?.url ?? ''),
      caption: item?.caption ?? '',
      category: item?.category ?? '',
    }));
    const videosRaw = Array.isArray(profile.videos) ? profile.videos : [];
    const videos = videosRaw.map((item: VideoItemStored) => ({
      id: item?.id ?? '',
      url: item?.file_path ? mediaPath(organizationId, 'video', item.id) : (item?.url ?? ''),
      title: item?.title ?? '',
      thumbnail: item?.thumbnail,
      description: item?.description,
      duration: item?.duration,
      category: item?.category,
    }));
    const coverImagesRaw =
      Array.isArray(profile.cover_images) && profile.cover_images.length > 0
        ? profile.cover_images
        : profile.cover_image
          ? [profile.cover_image]
          : [];
    const coverImages = usePublicMedia
      ? coverImagesRaw.map((p) => this.toPublicMediaPath(p) ?? p)
      : coverImagesRaw;
    const amenitiesNormalized = this.normalizeAmenitiesFromDb(profile.amenities);

    return {
      id: profile.id,
      organization_id: profile.organization_id,
      company_name: profile.company_name,
      logo: usePublicMedia ? (this.toPublicMediaPath(profile.logo) ?? profile.logo) : profile.logo,
      cover_image:
        coverImages[0] ??
        (usePublicMedia ? this.toPublicMediaPath(profile.cover_image) : profile.cover_image) ??
        null,
      cover_images: coverImages,
      organization_type: profile.organization_type,
      description: profile.description,
      phone: profile.phone,
      email: profile.email,
      fax: profile.fax ?? null,
      website: profile.website,
      address_line_1: profile.address_line_1 ?? null,
      address_line_2: profile.address_line_2 ?? null,
      city: profile.city ?? null,
      state: profile.state ?? null,
      zip_code: profile.zip_code ?? null,
      country: profile.country ?? null,
      business_hours: profile.business_hours ?? null,
      service_area: profile.service_area ?? null,
      coverage_radius: profile.coverage_radius,
      selected_services: profile.selected_services ?? null,
      licenses: profile.licenses ?? null,
      certifications: profile.certifications ?? null,
      gallery,
      videos,
      packages: profile.packages ?? [],
      specialty_services: profile.specialty_services ?? null,
      accepted_insurance: profile.accepted_insurance ?? null,
      amenities: amenitiesNormalized,
      room_types: profile.room_types ?? null,
      equipment_catalog: profile.equipment_catalog ?? null,
      transport_types: profile.transport_types ?? null,
      availability_status: profile.availability_status,
      rating: profile.rating != null ? Number(profile.rating) : null,
      review_count: profile.review_count ?? null,
      reviews: (Array.isArray(profile.reviews) ? profile.reviews : []).map(
        (r: {
          id?: string;
          author?: string;
          rating?: number;
          text?: string;
          date?: string;
          reply?: string;
          replied_at?: string;
          repliedAt?: string;
        }) => ({
          id: r?.id ?? '',
          author: r?.author ?? '',
          rating: r?.rating ?? 0,
          text: r?.text ?? '',
          date: r?.date ?? '',
          reply: r?.reply,
          replied_at: r?.replied_at ?? r?.repliedAt,
        }),
      ),
      created_at: profile.created_at,
      updated_at: profile.updated_at,
    };
  }

  private static readonly BASE_COLUMNS =
    'id, organization_id, company_name, logo, cover_image, organization_type, description, phone, email, website, address_line_1, address_line_2, city, state, zip_code, country, business_hours, service_area, coverage_radius, selected_services, licenses, certifications, gallery, videos, packages, specialty_services, accepted_insurance, amenities, room_types, equipment_catalog, transport_types, availability_status, rating, review_count, reviews, created_at, updated_at';

  /**
   * Load profile using raw query (only columns that always exist).
   * Use when entity columns (e.g. fax, cover_images) are missing in DB so findOne() would throw.
   */
  private async getByOrganizationIdRaw(
    organizationId: string,
  ): Promise<OrganizationCompanyProfile | null> {
    const rows = await this.profileRepository.query(
      `SELECT ${OrganizationCompanyProfileService.BASE_COLUMNS} FROM organization_company_profiles WHERE organization_id = $1 LIMIT 1`,
      [organizationId],
    );
    const row = rows[0];
    if (!row) return null;
    return {
      ...row,
      cover_images: [],
      fax: null,
      address_line_1: row.address_line_1 ?? null,
      address_line_2: row.address_line_2 ?? null,
      city: row.city ?? null,
      state: row.state ?? null,
      zip_code: row.zip_code ?? null,
      country: row.country ?? null,
    } as OrganizationCompanyProfile;
  }

  /**
   * Same as getByOrganizationIdRaw but match by URL slug (normalized company_name).
   * Uses only base columns so it works when fax/cover_images are missing.
   */
  private async getPublicBySlugRaw(slug: string): Promise<OrganizationCompanyProfile | null> {
    const rows = await this.profileRepository.query(
      `SELECT ${OrganizationCompanyProfileService.BASE_COLUMNS} FROM organization_company_profiles
       WHERE TRIM(BOTH '-' FROM LOWER(TRIM(REGEXP_REPLACE(COALESCE(company_name, ''), '[^a-z0-9]+', '-', 'gi')))) = $1
       LIMIT 1`,
      [slug],
    );
    const row = rows[0];
    if (!row) return null;
    return {
      ...row,
      cover_images: [],
      fax: null,
      address_line_1: row.address_line_1 ?? null,
      address_line_2: row.address_line_2 ?? null,
      city: row.city ?? null,
      state: row.state ?? null,
      zip_code: row.zip_code ?? null,
      country: row.country ?? null,
    } as OrganizationCompanyProfile;
  }

  async getByOrganizationId(
    organizationId: string,
    userId: string,
  ): Promise<CompanyProfileResponse | null> {
    try {
      await this.ensureAccess(organizationId, userId);
      let profile: OrganizationCompanyProfile | null = null;
      try {
        profile = await this.profileRepository.findOne({
          where: { organization_id: organizationId },
        });
      } catch (findError: unknown) {
        const msg = findError instanceof Error ? findError.message : String(findError);
        this.logger.warn(`getByOrganizationId: findOne failed, trying raw fallback. ${msg}`);
        try {
          profile = await this.getByOrganizationIdRaw(organizationId);
        } catch (rawError) {
          this.logger.warn(
            `getByOrganizationId: raw fallback failed. ${rawError instanceof Error ? rawError.message : rawError}`,
          );
          return null;
        }
      }
      if (!profile) return null;
      return this.mapProfileToResponse(profile, organizationId, false);
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `getByOrganizationId failed: ${error instanceof Error ? error.message : error}`,
      );
      throw new InternalServerErrorException(
        'Failed to load company profile. Please try again later.',
      );
    }
  }

  /** Get profile for public view (no auth); returns null if not found. Media URLs use public-media path. */
  async getPublicByOrganizationId(organizationId: string): Promise<CompanyProfileResponse | null> {
    try {
      let profile: OrganizationCompanyProfile | null = null;
      try {
        profile = await this.profileRepository.findOne({
          where: { organization_id: organizationId },
        });
      } catch (findError: unknown) {
        const msg = findError instanceof Error ? findError.message : String(findError);
        this.logger.warn(`getPublicByOrganizationId: findOne failed, trying raw fallback. ${msg}`);
        try {
          profile = await this.getByOrganizationIdRaw(organizationId);
        } catch (rawError) {
          this.logger.warn(
            `getPublicByOrganizationId: raw fallback failed. ${rawError instanceof Error ? rawError.message : rawError}`,
          );
          return null;
        }
      }
      if (!profile) return null;
      return this.mapProfileToResponse(profile, organizationId, true);
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `getPublicByOrganizationId failed: ${error instanceof Error ? error.message : error}`,
      );
      return null;
    }
  }

  /** Normalize company name to URL slug: lowercase, replace non-alphanumeric with hyphen, trim. */
  private static slugify(name: string | null | undefined): string {
    if (name == null || typeof name !== 'string') return '';
    return name
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  /**
   * Check whether a company name is available for the given organization.
   * Returns { available: true } if no other org uses the same slug, { available: false } otherwise.
   */
  async checkNameAvailability(
    organizationId: string,
    name: string,
  ): Promise<{ available: boolean; slug: string }> {
    const slug = OrganizationCompanyProfileService.slugify(name);
    if (!slug) return { available: false, slug };
    const rows = await this.profileRepository.query(
      `SELECT id FROM organization_company_profiles
       WHERE organization_id != $1
       AND TRIM(BOTH '-' FROM LOWER(TRIM(REGEXP_REPLACE(COALESCE(company_name, ''), '[^a-z0-9]+', '-', 'gi')))) = $2
       LIMIT 1`,
      [organizationId, slug],
    );
    return { available: rows.length === 0, slug };
  }

  /** Get profile for public view by slug (URL-friendly name). Returns null if not found. Never throws 500. */
  async getPublicBySlug(slug: string): Promise<CompanyProfileResponse | null> {
    if (!slug || typeof slug !== 'string') return null;
    const normalizedSlug = OrganizationCompanyProfileService.slugify(slug);
    if (!normalizedSlug) return null;
    let profile: OrganizationCompanyProfile | null = null;
    try {
      const profiles = await this.profileRepository
        .createQueryBuilder('p')
        .where(
          "TRIM(BOTH '-' FROM LOWER(TRIM(REGEXP_REPLACE(COALESCE(p.company_name, ''), '[^a-z0-9]+', '-', 'gi')))) = :slug",
          { slug: normalizedSlug },
        )
        .getMany();
      profile = profiles[0] ?? null;
    } catch (findError: unknown) {
      const msg = findError instanceof Error ? findError.message : String(findError);
      this.logger.warn(`getPublicBySlug: query failed, trying raw fallback. ${msg}`);
      try {
        profile = await this.getPublicBySlugRaw(normalizedSlug);
      } catch (rawError) {
        this.logger.warn(
          `getPublicBySlug: raw fallback failed. ${rawError instanceof Error ? rawError.message : rawError}`,
        );
        return null;
      }
    }
    if (!profile) return null;
    return this.mapProfileToResponse(profile, profile.organization_id, true);
  }

  /** Normalize amenities from DB: may be legacy string[] or object[]. */
  private normalizeAmenitiesFromDb(
    raw: OrganizationCompanyProfile['amenities'],
  ): AmenityItemResponse[] | null {
    if (raw == null) return null;
    if (!Array.isArray(raw)) return null;
    if (raw.length === 0) return [];
    const first = raw[0];
    if (typeof first === 'string') {
      return (raw as string[]).map((name) => ({ name, image_url: null, price: null }));
    }
    return (raw as Array<{ name?: string; image_url?: string; price?: string }>).map((a) => ({
      name: a?.name ?? '',
      image_url: a?.image_url ?? null,
      price: a?.price ?? null,
    }));
  }

  /** Normalize amenities from DTO for storage. */
  private normalizeAmenitiesForDb(
    incoming: Array<{ name?: string; image_url?: string; price?: string }> | undefined,
  ): Array<{ name: string; image_url?: string; price?: string }> | null {
    if (!incoming || !Array.isArray(incoming)) return null;
    return incoming
      .map((a) => ({
        name: typeof a?.name === 'string' ? a.name : '',
        image_url: a?.image_url,
        price: a?.price,
      }))
      .filter((a) => a.name !== '');
  }

  /** Extract gallery file id from a path like ".../media/gallery/UUID" or ".../public-media/gallery/UUID". */
  private getGalleryIdFromPath(path: string | null | undefined): string | null {
    if (!path || typeof path !== 'string') return null;
    const match = path.match(/\/gallery\/([a-f0-9-]+)$/i);
    return match ? match[1] : null;
  }

  private mergeGallery(
    existing: GalleryItemStored[],
    incoming: Array<{ id: string; url?: string; caption?: string; category?: string }>,
    keepReferencedIds?: string[],
  ): GalleryItemStored[] {
    const byId = new Map(existing.map((e) => [e.id, e]));
    const incomingIds = new Set(incoming.map((i) => i.id));
    const merged = incoming.map((item) => {
      const prev = byId.get(item.id);
      return {
        id: item.id,
        file_path: prev?.file_path,
        url: prev?.file_path ? undefined : item.url,
        caption: item.caption ?? prev?.caption ?? '',
        category: item.category ?? prev?.category ?? '',
      };
    });
    if (keepReferencedIds?.length) {
      for (const id of keepReferencedIds) {
        if (incomingIds.has(id)) continue;
        const existingItem = byId.get(id);
        if (existingItem) {
          merged.push({
            id: existingItem.id,
            file_path: existingItem.file_path,
            url: existingItem.file_path ? undefined : existingItem.url,
            caption: existingItem.caption ?? '',
            category: existingItem.category ?? '',
          });
        }
      }
    }
    return merged;
  }

  private mergeVideos(
    existing: VideoItemStored[],
    incoming: Array<{
      id: string;
      url?: string;
      title: string;
      thumbnail?: string;
      description?: string;
      duration?: string;
      category?: string;
    }>,
  ): VideoItemStored[] {
    const byId = new Map(existing.map((e) => [e.id, e]));
    return incoming.map((item) => {
      const prev = byId.get(item.id);
      return {
        id: item.id,
        file_path: prev?.file_path,
        url: prev?.file_path ? undefined : item.url,
        title: item.title,
        thumbnail: item.thumbnail ?? prev?.thumbnail,
        description: item.description ?? prev?.description,
        duration: item.duration ?? prev?.duration,
        category: item.category ?? prev?.category,
      };
    });
  }

  async upsert(
    organizationId: string,
    dto: UpdateOrganizationCompanyProfileDto,
    userId: string,
  ): Promise<CompanyProfileResponse> {
    await this.ensureAccess(organizationId, userId);
    let profile: OrganizationCompanyProfile | null = null;
    try {
      profile = await this.profileRepository.findOne({
        where: { organization_id: organizationId },
      });
    } catch {
      try {
        profile = await this.getByOrganizationIdRaw(organizationId);
      } catch {
        profile = null;
      }
    }
    if (!profile) {
      profile = this.profileRepository.create({
        organization_id: organizationId,
        gallery: [],
        videos: [],
        packages: [],
        reviews: [],
        cover_images: [],
        fax: null,
      });
    }

    if (dto.company_name !== undefined) profile.company_name = dto.company_name;
    const companyNameTrimmed = profile.company_name?.trim() ?? '';
    if (!companyNameTrimmed) {
      throw new BadRequestException('Company name is required.');
    }
    const slugNorm = OrganizationCompanyProfileService.slugify(profile.company_name);
    const duplicateRows = await this.profileRepository.query(
      `SELECT id FROM organization_company_profiles
       WHERE organization_id != $1
       AND TRIM(BOTH '-' FROM LOWER(TRIM(REGEXP_REPLACE(COALESCE(company_name, ''), '[^a-z0-9]+', '-', 'gi')))) = $2
       LIMIT 1`,
      [organizationId, slugNorm],
    );
    if (duplicateRows.length > 0) {
      throw new ConflictException(
        'Another organization already uses this company name. Company names must be unique.',
      );
    }
    if (dto.logo !== undefined) profile.logo = dto.logo;
    if (dto.cover_image !== undefined) profile.cover_image = dto.cover_image;
    if (dto.organization_type !== undefined) profile.organization_type = dto.organization_type;
    if (dto.description !== undefined) profile.description = dto.description;
    if (dto.phone !== undefined) profile.phone = dto.phone;
    if (dto.email !== undefined) profile.email = dto.email;
    if (dto.fax !== undefined) profile.fax = dto.fax;
    if (dto.website !== undefined) profile.website = dto.website;
    if (dto.cover_images !== undefined) {
      profile.cover_images = Array.isArray(dto.cover_images) ? dto.cover_images : [];
      profile.cover_image = profile.cover_images[0] ?? null;
    }
    if (dto.address_line_1 !== undefined) profile.address_line_1 = dto.address_line_1;
    if (dto.address_line_2 !== undefined) profile.address_line_2 = dto.address_line_2;
    if (dto.city !== undefined) profile.city = dto.city;
    if (dto.state !== undefined) profile.state = dto.state;
    if (dto.zip_code !== undefined) profile.zip_code = dto.zip_code;
    if (dto.country !== undefined) profile.country = dto.country;
    if (dto.business_hours !== undefined) profile.business_hours = dto.business_hours;
    if (dto.service_area !== undefined) profile.service_area = dto.service_area;
    if (dto.coverage_radius !== undefined) profile.coverage_radius = dto.coverage_radius;
    if (dto.selected_services !== undefined) profile.selected_services = dto.selected_services;
    if (dto.licenses !== undefined) profile.licenses = dto.licenses;
    if (dto.certifications !== undefined) profile.certifications = dto.certifications;
    if (dto.packages !== undefined) profile.packages = dto.packages;
    if (dto.specialty_services !== undefined) profile.specialty_services = dto.specialty_services;
    if (dto.accepted_insurance !== undefined) profile.accepted_insurance = dto.accepted_insurance;
    if (dto.amenities !== undefined) {
      const normalized = this.normalizeAmenitiesForDb(dto.amenities);
      profile.amenities = normalized;
    }
    if (dto.room_types !== undefined) profile.room_types = dto.room_types;
    if (dto.equipment_catalog !== undefined) profile.equipment_catalog = dto.equipment_catalog;
    if (dto.transport_types !== undefined) profile.transport_types = dto.transport_types;
    if (dto.availability_status !== undefined)
      profile.availability_status = dto.availability_status;
    if (dto.rating !== undefined) profile.rating = dto.rating;
    if (dto.review_count !== undefined) profile.review_count = dto.review_count;
    if (dto.reviews !== undefined) profile.reviews = dto.reviews;

    if (dto.gallery !== undefined) {
      const referencedIds: string[] = [];
      const logoId = this.getGalleryIdFromPath(dto.logo ?? profile.logo);
      if (logoId) referencedIds.push(logoId);
      const coverImages = (dto.cover_images ?? profile.cover_images) as string[] | undefined;
      if (coverImages?.length) {
        for (const path of coverImages) {
          const id = this.getGalleryIdFromPath(path);
          if (id && !referencedIds.includes(id)) referencedIds.push(id);
        }
      }
      profile.gallery = this.mergeGallery(profile.gallery ?? [], dto.gallery, referencedIds);
    }
    if (dto.videos !== undefined) {
      profile.videos = this.mergeVideos(profile.videos ?? [], dto.videos);
    }

    try {
      const saved = await this.profileRepository.save(profile);
      return this.mapProfileToResponse(saved, organizationId, false);
    } catch (saveError: unknown) {
      const msg = saveError instanceof Error ? saveError.message : String(saveError);
      if (msg.includes('column') && (msg.includes('does not exist') || msg.includes('undefined'))) {
        this.logger.warn(`upsert: save failed (missing column). Run migration 20260318. ${msg}`);
        throw new BadRequestException(
          'Company profile could not be saved. The database may need an update. Please try again later or contact support.',
        );
      }
      throw saveError;
    }
  }

  async confirmGalleryUpload(
    organizationId: string,
    payload: { key: string; caption: string; category: string },
    userId: string,
  ): Promise<{ id: string; url: string }> {
    await this.ensureAccess(organizationId, userId);
    const exists = await this.storageService.verifyUploaded(payload.key);
    if (!exists) {
      throw new BadRequestException('Uploaded file not found in storage. Retry the upload.');
    }
    const file_path = payload.key;
    const { caption, category } = payload;
    const id = randomUUID();
    let profile: OrganizationCompanyProfile | null = null;
    try {
      profile = await this.profileRepository.findOne({
        where: { organization_id: organizationId },
      });
    } catch {
      try {
        profile = await this.getByOrganizationIdRaw(organizationId);
      } catch {
        profile = null;
      }
    }
    if (!profile) {
      profile = this.profileRepository.create({
        organization_id: organizationId,
        gallery: [],
        videos: [],
        packages: [],
        reviews: [],
        cover_images: [],
        fax: null,
      });
    }
    const gallery = [...(profile.gallery ?? []), { id, file_path, caption, category }];
    profile.gallery = gallery;
    try {
      await this.profileRepository.save(profile);
    } catch (saveError: unknown) {
      const msg = saveError instanceof Error ? saveError.message : String(saveError);
      if (msg.includes('column') && (msg.includes('does not exist') || msg.includes('undefined'))) {
        this.logger.warn(
          `uploadGalleryImage: save failed (missing column). Run migration 20260318. ${msg}`,
        );
        throw new BadRequestException(
          'Upload could not be saved. The database may need an update. Please try again later or contact support.',
        );
      }
      throw saveError;
    }
    const url = this.buildMediaPath(organizationId, 'gallery', id);
    return { id, url };
  }

  async confirmVideoUpload(
    organizationId: string,
    payload: {
      key: string;
      title: string;
      description?: string;
      duration?: string;
      category?: string;
    },
    userId: string,
  ): Promise<{ id: string; url: string }> {
    await this.ensureAccess(organizationId, userId);
    const exists = await this.storageService.verifyUploaded(payload.key);
    if (!exists) {
      throw new BadRequestException('Uploaded file not found in storage. Retry the upload.');
    }
    const file_path = payload.key;
    const metadata = {
      title: payload.title,
      description: payload.description,
      duration: payload.duration,
      category: payload.category,
    };
    const id = randomUUID();
    let profile: OrganizationCompanyProfile | null = null;
    try {
      profile = await this.profileRepository.findOne({
        where: { organization_id: organizationId },
      });
    } catch {
      try {
        profile = await this.getByOrganizationIdRaw(organizationId);
      } catch {
        profile = null;
      }
    }
    if (!profile) {
      profile = this.profileRepository.create({
        organization_id: organizationId,
        gallery: [],
        videos: [],
        packages: [],
        reviews: [],
        cover_images: [],
        fax: null,
      });
    }
    const videos = [
      ...(profile.videos ?? []),
      {
        id,
        file_path,
        title: metadata.title,
        description: metadata.description,
        duration: metadata.duration,
        category: metadata.category,
      },
    ];
    profile.videos = videos;
    try {
      await this.profileRepository.save(profile);
    } catch (saveError: unknown) {
      const msg = saveError instanceof Error ? saveError.message : String(saveError);
      if (msg.includes('column') && (msg.includes('does not exist') || msg.includes('undefined'))) {
        this.logger.warn(
          `uploadVideo: save failed (missing column). Run migration 20260318. ${msg}`,
        );
        throw new BadRequestException(
          'Upload could not be saved. The database may need an update. Please try again later or contact support.',
        );
      }
      throw saveError;
    }
    const url = this.buildMediaPath(organizationId, 'video', id);
    return { id, url };
  }

  async getMediaSignedUrl(
    organizationId: string,
    type: 'gallery' | 'video',
    fileId: string,
    userId: string,
  ): Promise<{ url: string; file_name: string }> {
    try {
      await this.ensureAccess(organizationId, userId);
      let profile: OrganizationCompanyProfile | null = null;
      try {
        profile = await this.profileRepository.findOne({
          where: { organization_id: organizationId },
        });
      } catch {
        try {
          profile = await this.getByOrganizationIdRaw(organizationId);
        } catch {
          profile = null;
        }
      }
      if (!profile) throw new NotFoundException('Company profile not found');
      const list = type === 'gallery' ? (profile.gallery ?? []) : (profile.videos ?? []);
      const item = list.find((x: { id: string; file_path?: string }) => x.id === fileId);
      if (!item?.file_path) {
        throw new NotFoundException(`${type} item not found or not an uploaded file`);
      }
      const fileName = item.file_path.split('/').pop() ?? 'file';
      const url = await this.storageService.getPresignedViewUrl(item.file_path);
      return { url, file_name: fileName };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `getMediaSignedUrl failed: ${error instanceof Error ? error.message : error}`,
      );
      throw new NotFoundException('Company profile or media not found.');
    }
  }

  /**
   * Load the organization's logo file as a buffer, for use as an inline
   * attachment (e.g. email templates). Returns null when the org has no
   * uploaded logo or when the underlying file cannot be read.
   *
   * `profile.logo` is stored as a media URL such as
   * `/v1/api/organizations/{orgId}/company-profile/media/gallery/{fileId}`.
   * We parse the gallery file id out of it, look up the gallery entry to get
   * the storage-relative path, then stream the bytes into memory.
   */
  async getOrganizationLogoBytes(
    organizationId: string,
  ): Promise<{ buffer: Buffer; contentType: string; file_name: string } | null> {
    try {
      let profile: OrganizationCompanyProfile | null = null;
      try {
        profile = await this.profileRepository.findOne({
          where: { organization_id: organizationId },
        });
      } catch {
        try {
          profile = await this.getByOrganizationIdRaw(organizationId);
        } catch {
          profile = null;
        }
      }
      if (!profile?.logo) {
        this.logger.log(
          `getOrganizationLogoBytes: org ${organizationId} has no logo configured; falling back to default.`,
        );
        return null;
      }
      const logo = profile.logo.trim();

      // External logo (fully-qualified http/https URL): download the bytes.
      if (/^https?:\/\//i.test(logo)) {
        try {
          const response = await fetch(logo);
          if (!response.ok) {
            this.logger.warn(
              `getOrganizationLogoBytes: external logo fetch failed for org ${organizationId} (${response.status} ${response.statusText}).`,
            );
            return null;
          }
          const arrayBuf = await response.arrayBuffer();
          const buffer = Buffer.from(arrayBuf);
          const contentType =
            response.headers.get('content-type') ?? 'application/octet-stream';
          const fileName = logo.split('/').pop()?.split('?')[0] || 'logo';
          return { buffer, contentType, file_name: fileName };
        } catch (err) {
          this.logger.warn(
            `getOrganizationLogoBytes: external logo fetch threw for org ${organizationId}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
          return null;
        }
      }

      // Internal gallery path: parse file id, find gallery item, read bytes.
      const match = logo.match(/\/gallery\/([a-f0-9-]+)(?:$|[/?#])/i);
      const fileId = match?.[1];
      if (!fileId) {
        this.logger.warn(
          `getOrganizationLogoBytes: org ${organizationId} logo path does not contain a /gallery/{id} segment (value: ${logo}).`,
        );
        return null;
      }
      const gallery = Array.isArray(profile.gallery) ? profile.gallery : [];
      const item = gallery.find((x) => x?.id === fileId);
      if (!item?.file_path) {
        this.logger.warn(
          `getOrganizationLogoBytes: org ${organizationId} gallery has no item with id ${fileId} (or item missing file_path). Gallery size: ${gallery.length}.`,
        );
        return null;
      }
      const fileName = item.file_path.split('/').pop() ?? 'logo';
      const buffer = await this.s3Service.getObjectAsBuffer(item.file_path);
      const contentType = this.guessContentTypeFromName(fileName);
      return { buffer, contentType, file_name: fileName };
    } catch (error) {
      this.logger.warn(
        `getOrganizationLogoBytes failed for org ${organizationId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return null;
    }
  }

  /** Signed GET URL for public media view (e.g. landing page); no auth. */
  async getMediaSignedUrlPublic(
    organizationId: string,
    type: 'gallery' | 'video',
    fileId: string,
  ): Promise<{ url: string; file_name: string }> {
    try {
      let profile: OrganizationCompanyProfile | null = null;
      try {
        profile = await this.profileRepository.findOne({
          where: { organization_id: organizationId },
        });
      } catch {
        try {
          profile = await this.getByOrganizationIdRaw(organizationId);
        } catch {
          profile = null;
        }
      }
      if (!profile) throw new NotFoundException('Company profile not found');
      const list = type === 'gallery' ? (profile.gallery ?? []) : (profile.videos ?? []);
      const item = list.find((x: { id: string; file_path?: string }) => x.id === fileId);
      if (!item?.file_path) {
        throw new NotFoundException(`${type} item not found or not an uploaded file`);
      }
      const fileName = item.file_path.split('/').pop() ?? 'file';
      const url = await this.storageService.getPresignedViewUrl(item.file_path);
      return { url, file_name: fileName };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `getMediaSignedUrlPublic failed: ${error instanceof Error ? error.message : error}`,
      );
      throw new NotFoundException('Company profile or media not found.');
    }
  }

  private guessContentTypeFromName(filename: string): string {
    const ext = filename.toLowerCase().split('.').pop() ?? '';
    const map: Record<string, string> = {
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      png: 'image/png',
      gif: 'image/gif',
      webp: 'image/webp',
      svg: 'image/svg+xml',
      mp4: 'video/mp4',
      webm: 'video/webm',
      mov: 'video/quicktime',
    };
    return map[ext] ?? 'application/octet-stream';
  }
}
