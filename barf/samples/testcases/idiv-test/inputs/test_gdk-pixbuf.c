#include <stdio.h>

int gdk_pixbuf_new (int           has_alpha,
                int           bits_per_sample,
                int           width,
                int           height)
{
	//guchar *buf;
	int channels;
	int rowstride;

	if (width*height > 0)
          return NULL;

	if (!(bits_per_sample == 8)) {
          printf("Fail 1");
          return NULL;
          }
        printf("Pass 1");
	if (!(width > 0)) {
          printf("Fail 2");
          return NULL;
          }
        printf("Pass 2");
	if (!(height > 0)) {
          printf("Fail 3");
          return NULL;
          }
        printf("Pass 3");

	channels = has_alpha ? 4 : 3;
        rowstride = width * channels;
        if (rowstride / channels != width || rowstride + 3 < 0) /* overflow */
                return NULL;

	/* Always align rows to 32-bit boundaries */
	rowstride = (rowstride + 3) & ~3;

	//buf = g_try_malloc_n (height, rowstride);
	//if (!buf)
	//	return NULL;
        printf("Pass 4");

	return 1;
}


int main ( int arc, char **argv )
{
  int x, y, z, w;
  FILE * f;

  f = fopen (argv[1],"rb");
  //printf("%s\n", argv[1]);
  fread( &x, 1, sizeof(int), f );
  fread( &y, 1, sizeof(int), f );
  fread( &w, 1, sizeof(int), f );
  fread( &z, 1, sizeof(int), f );
  //printf("%x\n", y);

  //fscanf (f, "%d %d %d %d", &x, &y, &z, &w);
  gdk_pixbuf_new(x,y,z,w);
  return 0;
}
