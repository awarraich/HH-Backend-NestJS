import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { AddressesService } from './addresses.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CreateAddressDto } from './dto/create-address.dto';
import type { AddressInterface } from './interfaces/address.interface';

@Controller('v1/api/addresses')
@UseGuards(JwtAuthGuard)
export class AddressesController {
  constructor(private readonly addressesService: AddressesService) {}

  @Get()
  findAll(): Promise<AddressInterface[]> {
    return this.addressesService.findAll();
  }

  @Post()
  create(@Body() createAddressDto: CreateAddressDto): Promise<AddressInterface> {
    return this.addressesService.create(createAddressDto);
  }
}
