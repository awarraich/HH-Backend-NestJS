import {
  BadRequestException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import { PDFDocument } from 'pdf-lib';
import { OfferLetterSigningToken } from '../entities/offer-letter-signing-token.entity';
import { JobApplication } from '../entities/job-application.entity';
import { JobApplicationDocumentStorageService } from './job-application-document-storage.service';

export interface CreateTokenInput {
  offerLetterApplicationId: string;
  candidateEmail: string;
  candidateName: string;
  jobTitle: string;
  organizationId: string;
  pdfUrl: string;
  signaturePosition?: {
    pageNumber: number;
    x: number;
    y: number;
    width: number;
    height: number;
  };
}

export interface SignOfferInput {
  signatureImageBase64: string;
  signedAt?: string;
  ipAddress?: string;
  userAgent?: string;
  signaturePosition?: {
    pageNumber: number;
    x: number;
    y: number;
    width: number;
    height: number;
  };
}

const DEFAULT_TOKEN_TTL_DAYS = 7;

@Injectable()
export class OfferLetterSigningService {
  private readonly logger = new Logger(OfferLetterSigningService.name);

  constructor(
    @InjectRepository(OfferLetterSigningToken)
    private readonly tokenRepo: Repository<OfferLetterSigningToken>,
    @InjectRepository(JobApplication)
    private readonly applicationRepo: Repository<JobApplication>,
    private readonly configService: ConfigService,
    private readonly documentStorage: JobApplicationDocumentStorageService,
  ) {}

  async createToken(input: CreateTokenInput): Promise<{ token: string; expiresAt: Date }> {
    const ttlDays = Number(
      this.configService.get<string>('OFFER_LETTER_SIGNING_TTL_DAYS') ?? DEFAULT_TOKEN_TTL_DAYS,
    );
    const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);
    const token = randomBytes(48).toString('base64url');

    const defaultPosition = {
      pageNumber: 1,
      x: 72,
      y: 120,
      width: 220,
      height: 60,
    };

    const entity = this.tokenRepo.create({
      token,
      job_application_id: input.offerLetterApplicationId,
      candidate_email: input.candidateEmail,
      candidate_name: input.candidateName,
      job_title: input.jobTitle,
      organization_id: input.organizationId,
      pdf_url: input.pdfUrl,
      signature_position: (input.signaturePosition ?? defaultPosition) as Record<string, unknown>,
      expires_at: expiresAt,
    });
    await this.tokenRepo.save(entity);
    return { token, expiresAt };
  }

  /** Validate token and return metadata for GET /offer-letter/sign/:token. */
  async getByToken(token: string): Promise<{
    candidateName: string;
    jobTitle: string;
    pdfUrl: string;
    signaturePosition: Record<string, unknown> | null;
    expiresAt: Date;
  }> {
    const record = await this.findActiveToken(token);
    return {
      candidateName: record.candidate_name,
      jobTitle: record.job_title,
      pdfUrl: record.pdf_url,
      signaturePosition: record.signature_position,
      expiresAt: record.expires_at,
    };
  }

  async signOffer(
    token: string,
    input: SignOfferInput,
  ): Promise<{ signedPdfUrl: string; signedAt: Date }> {
    const record = await this.findActiveToken(token);

    const pdfBytes = await this.downloadPdf(record.pdf_url);
    const signaturePng = this.decodeSignaturePng(input.signatureImageBase64);

    const pdfDoc = await PDFDocument.load(pdfBytes);
    const pngImage = await pdfDoc.embedPng(signaturePng);

    const pos = (input.signaturePosition ??
      record.signature_position ??
      {}) as {
      pageNumber?: number;
      x?: number;
      y?: number;
      width?: number;
      height?: number;
    };
    const pageIndex = Math.max(0, (pos.pageNumber ?? 1) - 1);
    const pages = pdfDoc.getPages();
    if (pageIndex >= pages.length) {
      throw new BadRequestException('Invalid signature position: page out of range');
    }
    const page = pages[pageIndex];
    const width = pos.width ?? 220;
    const height = pos.height ?? 60;
    const x = pos.x ?? 72;
    // Convert from top-left origin (frontend) to PDF's bottom-left origin.
    const yTop = pos.y ?? 120;
    const pdfY = page.getHeight() - yTop - height;

    page.drawImage(pngImage, { x, y: pdfY, width, height });

    // Snapshot the actual position used (for the org-side viewer).
    const usedPosition = {
      pageNumber: pageIndex + 1,
      x,
      y: yTop,
      width,
      height,
    };

    const signedPdfBytes = Buffer.from(await pdfDoc.save());
    const signedFilename = `signed-offer-${record.id}.pdf`;
    const { file_url: signedPdfUrl } = await this.documentStorage.saveDocument(
      signedPdfBytes,
      signedFilename,
    );

    const signedAt = new Date();
    record.used_at = signedAt;
    record.signed_pdf_url = signedPdfUrl;
    record.audit_trail = {
      signedAt: signedAt.toISOString(),
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
      clientSuppliedSignedAt: input.signedAt ?? null,
    };
    await this.tokenRepo.save(record);

    await this.updateApplication(record, signedPdfUrl, signedAt, usedPosition);

    this.logger.log(
      `Offer letter signed: token=${maskToken(token)} application=${record.job_application_id}`,
    );
    return { signedPdfUrl, signedAt };
  }

  private async findActiveToken(token: string): Promise<OfferLetterSigningToken> {
    if (!token || token.length < 16) {
      throw new NotFoundException('Signing link is invalid');
    }
    const record = await this.tokenRepo.findOne({ where: { token } });
    if (!record) {
      throw new NotFoundException('Signing link is invalid');
    }
    if (record.used_at) {
      throw new GoneException('This signing link has already been used');
    }
    if (record.expires_at.getTime() < Date.now()) {
      throw new GoneException('This signing link has expired');
    }
    return record;
  }

  private async downloadPdf(url: string): Promise<Uint8Array> {
    try {
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`Failed to fetch offer PDF: ${res.status}`);
      }
      const arrayBuffer = await res.arrayBuffer();
      return new Uint8Array(arrayBuffer);
    } catch (err) {
      this.logger.error(`Failed to download offer PDF: ${(err as Error).message}`);
      throw new BadRequestException('Unable to download the offer letter PDF for signing');
    }
  }

  private decodeSignaturePng(base64: string): Buffer {
    const cleaned = base64.replace(/^data:image\/(png|jpeg|jpg);base64,/i, '');
    try {
      return Buffer.from(cleaned, 'base64');
    } catch {
      throw new BadRequestException('Invalid signature image');
    }
  }

  private async updateApplication(
    record: OfferLetterSigningToken,
    signedPdfUrl: string,
    signedAt: Date,
    signaturePosition: {
      pageNumber: number;
      x: number;
      y: number;
      width: number;
      height: number;
    },
  ): Promise<void> {
    const application = await this.applicationRepo.findOne({
      where: { id: record.job_application_id },
    });
    if (!application) return;
    const prev = (application.offer_details ?? {}) as Record<string, unknown>;
    application.offer_details = {
      ...prev,
      signedPdfUrl,
      signed_pdf_url: signedPdfUrl,
      signedAt: signedAt.toISOString(),
      signed_at: signedAt.toISOString(),
      signaturePosition,
      signing_token_id: record.id,
    };
    application.status = 'offer_signed';
    await this.applicationRepo.save(application);
  }

  /** Housekeeping: purge long-expired unused tokens. Callable from a cron job. */
  async purgeExpired(olderThanDays = 30): Promise<number> {
    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    const result = await this.tokenRepo
      .createQueryBuilder()
      .delete()
      .where('expires_at < :cutoff', { cutoff })
      .andWhere('used_at IS NULL')
      .execute();
    return result.affected ?? 0;
  }
}

function maskToken(t: string): string {
  if (t.length <= 10) return '***';
  return `${t.slice(0, 4)}…${t.slice(-4)}`;
}
