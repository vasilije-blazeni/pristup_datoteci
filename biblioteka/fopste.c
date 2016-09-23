#include <time.h>				// time_t, time(), strftime(), localtime()
#include <sys/timeb.h>	// ftime()
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>


char
*standardan_format( const char *korisnicki_format, char *pravi_format )
{
//	#define MAX_DUZ_STAND_FORMATA		150	/* Najveca moguca duzina
//	 * stringa (eventulno) preobracenog formata; rezervisemo dosta veliki bafer
//	 * za slucaj da se u izvornom, korisnickom formatu pojavi dugacak string. */

	char					*pchar, *specifikator, max_duz_dat_vrem = sizeof
		"DD.MM.GGGG.  cc:mm:ss.mis", format_dat_vrem[ max_duz_dat_vrem ];
//	static char		standardni_format[ MAX_DUZ_STAND_FORMATA + 1 ];
	struct timeb		vreme;


	if( ( pchar = strstr( korisnicki_format, "%V" ) ) != NULL )
	{	/* Korisnicki specifikator tipa konverzije koji oznacava vreme u obliku
		 * "cc:mm:ss". */
		specifikator = pchar;
		strcpy( format_dat_vrem, "%T" );
		pchar += 2;	/* Pomeramo pokazivac na polozaj neposredno iza do sada
		 * nadjenog dela korisnickog specifikatora tipa konverzije. */
	}
	else if( ( pchar = strstr( korisnicki_format, "%D" ) ) != NULL )
	{	/* Korisnicki specifikator tipa konverzije koji oznacava datum i vreme
		 *  (ocekuje se "%DV", pa ne vrsimo detaljnu proveru) u obliku
		 * "DD.MM.GG  cc:mm:ss". */
		specifikator = pchar;
		strcpy( format_dat_vrem, "%d.%m.%Y.  %T" );
		pchar += 3;	/* Pomeramo pokazivac na polozaj neposredno iza do sada
		 * nadjenog dela korisnickog specifikatora tipa konverzije. */
	}
	else	/* nema nijednog korisnickog specifikatora tipa konverzije, pa samo
		 * kopiramo korisnicki format u izlazni bafer. */
		return strcpy( pravi_format, korisnicki_format );

	/* zamena korisnickog specifikatora tipa konverzije "%[D]V" (koji bi doveo
	 * do greske) tekucim vremenom/datumom i vremenom u ASCII-formatu */
	ftime( &vreme );
	strncpy( pravi_format, korisnicki_format, specifikator - korisnicki_format );
	strftime( &pravi_format[ specifikator - korisnicki_format ],
		max_duz_dat_vrem, format_dat_vrem, localtime( &vreme.time ) );

	if( *pchar == 'm' )
	{	/* zamena dela korisnickog specifikatora tipa konverzije "m"
		 * milisekundama tekuceg vremena, u ASCII-formatu */
		sprintf( pravi_format + strlen( pravi_format ), ".%03hu",
			vreme.millitm );
		pchar++;	/* Pomeramo pokazivac na polozaj neposredno iza korisnickog
		 * specifikatora tipa konverzije. */
	}

	return strcat( pravi_format, pchar );	/* Kopiramo ostatak formata iza
		 * korisnickog specifikatora tipa konverzije. */
}


void
izvestaj( const char *ime_izvestaja, const char *format,  ... )
/* VAZNA NAPOMENA: argument pre '...' mora biti tipa 'int' ili tipa koji ne
 * menja velicinu pri cast-ovanju u tip 'int' (pokazivacka promenljiva je tipa 'int' */
{
	static char		prvi_upis = 1;
	char					pravi_format[ strlen( format ) +
		sizeof( "DD.MM.GGGG.  cc:mm:ss.mis" ) ];
	int		fd;
	va_list	argumenti;
	FILE		*fp;


	/* kreiranje log-fajla ukoliko ne postoji i otvaranje istog */
    if( ( fp = fopen( ime_izvestaja, "a" ) ) != NULL )
    {
		if( ( fd = fileno( fp ) ) != -1 )
		{
			struct stat	pod_o_fajlu;

			if( ( fstat( fd, &pod_o_fajlu ) == 0 && pod_o_fajlu.st_size == 0 ) || prvi_upis )
			{	/* Log-fajl je sad kreiran ili se vrsi prvi upis nakon pokretanja
				 * taska - upisujemo dvostruku isprekidanu liniju pri prvom upisu,
				 * a u svim slucajevima verziju aplikacije, lokalno tekuce vreme s
				 * datumom (jer se kasnije upisuje bez datuma, radi kraceg log-
				 * -fajla), oznaku verzije i kodove stanice i trake.  */
				if( prvi_upis )
				{
					fprintf( fp, "\n==========================================="
						"=====================================\n\n\n" );
					prvi_upis = 0;
				}
			}
		}

		va_start( argumenti, format );
		vfprintf( fp, standardan_format( format, pravi_format ), argumenti );
		va_end( argumenti );

//		/* sinhronizovanje podataka fajla */
//		if( ( fd = fileno( fp ) ) != -1 )
//			fdatasync( fd );

		fclose( fp );
    }

	return;
}
