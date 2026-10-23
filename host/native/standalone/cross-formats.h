/* Closed cross-link formats; validators fail before any linker or loader runs. */
#ifndef KELFT_CROSS_FORMATS_H
#define KELFT_CROSS_FORMATS_H
static uint16_t cross16(const unsigned char *b) {return (uint16_t)b[0]|(uint16_t)b[1]<<8;}
static uint32_t cross32(const unsigned char *b) {return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
/* Closed five-section Kelft COFF format; .drectve, LTO and dependency-list
 * sections cannot inject flags or file reads into LLD. */
static void cross_object(const unsigned char *b,size_t n){
 static const unsigned char names[5][9]={".text",".rdata",".xdata",".pdata",".kelft$M"};
 static const uint32_t flags[]={0x60500020,0x40400040,0x40300040,0x40300040,0x40100040};
 if(n<242||cross16(b)!=0x8664||cross16(b+2)!=5||cross32(b+16))fail("unsupported Kelft cross COFF header");
 uint64_t symbols=cross32(b+8),count=cross32(b+12),strings=symbols+count*18;
 if(!count||symbols<220||strings>n-4||cross32(b+strings)<4||strings+cross32(b+strings)!=n)fail("invalid cross COFF symbols");
 for(unsigned i=0;i<5;i++){
  const unsigned char *s=b+20+i*40;uint64_t length=cross32(s+16),start=cross32(s+20),reloc=cross32(s+24),rows=cross16(s+32);uint32_t f=cross32(s+36);
  if(memcmp(s,names[i],8)||cross32(s+8)||cross32(s+12)||cross32(s+28)||cross16(s+34)||(f&~0x01000000U)!=flags[i])fail("unsupported cross COFF section");
  if(length&&(start<220||start+length>symbols))fail("cross COFF payload range");
  if(f&0x01000000U){if(rows!=65535||reloc<220||reloc+10>symbols)fail("cross COFF extended relocation range");rows=cross32(b+reloc);if(rows<=65536)fail("cross COFF extended count");}
  if(rows&&(reloc<220||reloc+rows*10>symbols))fail("cross COFF relocation range");
 }
}
static void cross_image(const unsigned char *b,size_t n){
 if(n<328||memcmp(b,"MZ",2))fail("cross output DOS header");
 uint64_t pe=cross32(b+60);
 if(pe<64||pe+264>n||memcmp(b+pe,"PE\0\0",4)||cross16(b+pe+4)!=0x8664||cross16(b+pe+20)!=240||cross16(b+pe+24)!=0x20b||(cross16(b+pe+22)&0x2002)!=2)fail("cross output PE architecture or kind");
 uint64_t opt=pe+24,table=opt+240,sections=cross16(b+pe+6);
 if(!sections||sections>96||table+sections*40>n||cross32(b+opt+108)<11)fail("cross output section table");
 uint64_t rva=cross32(b+opt+192),size=cross32(b+opt+196);unsigned found=0;
 if(!rva||size!=112||cross32(b+opt+72)!=16777216||cross32(b+opt+76)||cross32(b+opt+80)!=65536||cross32(b+opt+84))fail("cross output load policy or stack");
 for(unsigned i=0;i<sections;i++){
  const unsigned char *s=b+table+i*40;uint64_t start=cross32(s+12),length=cross32(s+16),offset=cross32(s+20);uint32_t f=cross32(s+36);
  if(length&&(offset<table+sections*40||offset+length>n))fail("cross output payload range");
  if((f&0xa0000000U)==0xa0000000U)fail("writable executable cross section");
  if(rva>=start&&rva-start<=length&&size<=length-(rva-start)){
   offset+=rva-start;if(++found!=1||(f&0xe0000000U)!=0x40000000U||offset+size>n||cross32(b+offset)!=size||cross16(b+offset+78)!=0x800)fail("cross output dependency policy");
  }
 }if(found!=1)fail("cross output immutable load configuration missing");
}
#endif
