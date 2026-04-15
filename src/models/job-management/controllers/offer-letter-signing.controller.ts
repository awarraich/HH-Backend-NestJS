import { Body, Controller, Get, Ip, Param, Post, Headers } from '@nestjs/common';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { OfferLetterSigningService } from '../services/offer-letter-signing.service';
import { SignOfferLetterDto } from '../dto/sign-offer-letter.dto';

/** Public (no JWT) — access is gated by the one-time signing token. */
@Controller('v1/api/offer-letter/sign')
export class OfferLetterSigningController {
  constructor(private readonly signingService: OfferLetterSigningService) {}

  @Get(':token')
  async getSigningContext(@Param('token') token: string) {
    const data = await this.signingService.getByToken(token);
    return SuccessHelper.createSuccessResponse(data, 'Offer letter loaded');
  }

  @Post(':token')
  async submitSignature(
    @Param('token') token: string,
    @Body() dto: SignOfferLetterDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent?: string,
  ) {
    const result = await this.signingService.signOffer(token, {
      signatureImageBase64: dto.signatureImageBase64,
      signedAt: dto.signedAt,
      signaturePosition: dto.signaturePosition,
      ipAddress: ip,
      userAgent,
    });
    return SuccessHelper.createSuccessResponse(result, 'Offer letter signed successfully');
  }
}
