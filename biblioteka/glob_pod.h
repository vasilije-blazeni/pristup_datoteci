#ifndef OPSTE_H
#define OPSTE_H

#include <stdio.h>		// sprintf()
#include <errno.h>		// errno
#include <string.h>		// strerror()
#include <time.h>		// strftime()
#include <sys/time.h>	// gettimeofday()

#define EOK	0 // U GNU/Linux-u nije definisana ova konstanta.

typedef struct
{
	int		kod;
	char	opis[ 500 ];
}	Kod_opis_gr;

#define INIC_KOD_OPIS_GR Kod_opis_gr	kod_opis_gr = { EOK, "" };

#if 0
/* VAZNE NAPOMENE:
 * - Pri koriscenju donjih makro-definicije voditi racuna da
 * duzina rezultujuceg stringa opisa greske ne dovede do prekoracenja
 * komponente strukture opis[ 500 ].
 * - Ako se sistemska greska ne pojavljuje u 'errno', vec u povratnoj vrednosti
 * bibliotecke funkcije, donja makro-definicija se moze koristiti tako sto se
 * kao parametar USLOV stavi if( ( errno = funkcija() ) != EOK ). */
#define USLOV_ZA_SIS_GR_I_NAREDBE(USLOV, NAREDBE) \
	USLOV \
	{ \
		kod_opis_gr.kod = errno; \
		struct timeval	vreme_s_us;	\
		gettimeofday( &vreme_s_us, NULL );	\
		strftime( kod_opis_gr.opis, sizeof( "00:00:00" ), "%T", localtime(	\
			&vreme_s_us.tv_sec ) );	\
		sprintf( kod_opis_gr.opis + strlen( kod_opis_gr.opis ),	\
			".%03ld  GRESKA %d (%s): %s, %s(), linija %d, " #USLOV,	\
			vreme_s_us.tv_usec / 1000, kod_opis_gr.kod,	\
			strerror( kod_opis_gr.kod ), __FILE__, __func__, __LINE__ ); \
		NAREDBE \
	}

#define USLOV_ZA_KOR_GR_I_NAREDBE(USLOV, KOD_GR, OPIS_GR, NAREDBE) \
	USLOV \
	{ \
		kod_opis_gr.kod = KOD_GR; \
		struct timeval	vreme_s_us;	\
		gettimeofday( &vreme_s_us, NULL );	\
		strftime( kod_opis_gr.opis, sizeof( "00:00:00" ), "%T", localtime(	\
			&vreme_s_us.tv_sec ) );	\
		sprintf( kod_opis_gr.opis + strlen( kod_opis_gr.opis ),	\
			".%03ld  GRESKA " KOD_GR " (" OPIS_GR "): %s, %s(), linija %d, "	\
			#USLOV,	vreme_s_us.tv_usec / 1000, __FILE__, __func__, __LINE__ ); \
		NAREDBE \
	}
#endif

/* VAZNE NAPOMENE:
 * - Pri koriscenju donjeg funkcijskog makroa voditi racuna da duzina rezultujuceg stringa
 * opisa greske ne dovede do prekoracenja komponente strukture opis[ 500 ].
 * - Ako se sistemska greska ne pojavljuje u 'errno', vec u povratnoj vrednosti
 * bibliotecke funkcije, donji funkcijski makro se moze koristiti tako sto se
 * kao parametar USLOV stavi if( ( errno = funkcija() ) != EOK ). */

#define USLOV_ZA_GR_KOD_I_OPIS_GR_I_NAREDBE(USLOV_ZA_GR, KOD_GR, OPIS_GR, NAREDBE) \
	USLOV_ZA_GR \
	{ \
		kod_opis_gr.kod = KOD_GR; \
		struct timeval	vreme_s_us;	\
		gettimeofday( &vreme_s_us, NULL );	\
		strftime( kod_opis_gr.opis, sizeof( "00:00:00" ), "%T", localtime(	\
			&vreme_s_us.tv_sec ) );	\
		sprintf( kod_opis_gr.opis + strlen( kod_opis_gr.opis ),	\
			".%03ld  GRESKA %d (%s): %s, %s(), linija %d, "	\
			#USLOV_ZA_GR, vreme_s_us.tv_usec / 1000, kod_opis_gr.kod,	\
			strerror( KOD_GR ), __FILE__, __func__, __LINE__ ); \
		NAREDBE \
	}
/* Za sistemsku gresku se poziva ovako:
 * USLOV_ZA_GR_KOD_I_OPIS_GR_I_NAREDBE
 * (
 *		USLOV_ZA_GR,
 *		errno, strerror( errno ),
 *		NAREDBE
 * );
 * */
typedef enum
{	/* VAZNA NAPOMENA: indeksi taskova moraju biti uskladjeni sa nizom
	 * ime_taska[] u fajlu "imena_taskova.c"; takodje, zbog jednostavnijeg
	 * uslova u tasku "tinic", indeksi taskova za testiranje periferijskih uredjaja
	 * treba da se nalaze na kraju. */
	TINIC,
	TKONZOLA,
	TPROMENA,
	TSTAMPAC,
	TPRIJAVLjIVANjE,
	BROJ_TASKOVA
}	INDEKS_PROCESA;


#define MAX_DUZ_TEKSTA		150
#define NAJV_DUZ_NASLOVA	51	/* Videti napomenu u opisu funkcije
	 * naslov_prozora() u datoteci "fkonzola.c" projekta "tkonzola". */


/************** Definicije konstanata zajednickih za vise taskova *************/

enum OPSTE_KONSTANTE
{	/* NAPOMENA: kod ovih konstanata sama vrednost nije od znacaja - mogu se
	 * slobodno dodavati ili umetati nove konstante. Vrednost 0 preskacemo jer
	 * nam moze biti od znacaja da se kod nekih promenljivih vrednost
	 * postavljena na neku od ovih konstanata razlikuje od pocetne 0, kojom
	 * oznacavamo "nedefinisanu" vrednost. */
	STOP = 1,								// tdisplej, tvozila

	/* Tip unosa podatka (ove konstante koriste funkcije editovanje_stringa()
	 * i unos_podatka()): */
	CEO_BROJ,
	VISE_CELIH_BROJEVA,
	REALAN_BROJ,
	SLOVA,
	TEKST,
	TEKST_VEL_SLOVA,
	// novo:
	KARAKTER,	// bez eventualnog upisa u resurs teksta widget-a
	LOZINKA
};



enum SPECIJALNI_TASTER
{	/* VAZNA NAPOMENA: vrednosti ovih kodova moraju se ne smeju preklapati sa
	 * podskupom ASCII kodova koji u aplikaciji koristimo direktno - "Basic
	 * Latin" iz fajla zaglavlja <photon/PkKeyDef.h>, koji pocinje sa'Pk_space'
	 * (0x020), a zavrsava se sa 'Pk_asciitilde' (0x07e); takodje, ne smeju da
	 * izadju iz opsega za tip 'char' (najveca vrednost 0xff) - u protivnom bi
	 * funkcije za manipulaciju karakterima, poput isalnum(), "pukle", iako im
	 * je argument tipa 'int', niti neki kod sme imati vrednost 0, jer se ona
	 * koristi u callback-funkciji 'cb_taster()' u fajlu "cb_funkcije.h" projekta
	 * "tkonzola" za oznacavanje da nije pritisnut taster ciji kod treba proslediti
	 * zainteresovanom tasku */
	ENTER = -128,	/* kodovi cije vrednosti prelaze vrednost 0x7f moraju biti
	 * definisani kao negativni brojevi (ne moze, npr. 0xff), da se ne bi javljala
	 * greska u aplikaciji pri poredjenju tih vrednosti s podacima tipa 'char' */
	ESC,
	TAB,
	BACKSPACE,
	DEL,
	INS,

	UP,
	DOWN,
	LEFT,
	RIGHT,
/*	HOME,
 * 	END, 		koriste se samo za pomeranje na pocetak/kraj u PtList */
	PGUP,				// staviti pod komentar
	PGDOWN,		// staviti pod komentar

//	F1,		// hotkey za prikazivanje spiska hotkey-tastera
	F2,		// taskovi za testiranje uredjaja
	F3,		// taskovi za testiranje uredjaja
	F4,		// taskovi za testiranje uredjaja
	F5,		// taskovi za testiranje uredjaja
	F6,		// taskovi za testiranje uredjaja
	F7,		// taskovi za testiranje uredjaja
//	F8,		// hotkey za izbor analognog casovnika
//	F9,		// hotkey za listanje pregleda dogadjanja u sistemu (samo kada
				// task TKONZOLA radi u servisnom rezimu)
//	F10,		// hotkey za prikaz/brisanje prozora s najvaznijim podacima o
				// poslednjoj ENP-transakciji.
//	F11,		// hotkey za pocetak/kraj neprestanog prikazivanja vozila
//	F12,		// hotkey za pocetak/kraj prikazivanja neregularnosti u radu periferijskih uredjaja

	ALT_B,		// bezgotovinska naplata (TNAPLATA)
	ALT_D,		// hotkey za vadjenje zaboravljene kreditne/debitne kartice i
					// deblokiranje automatske naplate - prosledjuje se njegova vrednost
	ALT_I,
	ALT_O,
	ALT_P,		// prekoredna naplata (TNAPLATA)
//	ALT_R,		//  hotkey za zatvaranje dijaloga za alarm

	ALT_T,		// ocitavanje/stampanje test-kartice (TNAPLATA/TDISTRIBUCIJA)
	ALT_V,		// rucno signalizovanje dolaska vozila

	ALT_F1,		// spustanje rampe nakon prolaska vozila pod prioritetom
	ALT_F10,	// podizanje rampe pri prolasku vozila pod prioritetom

	SHIFT_F1,	// reset rampe
	SHIFT_F2,	// taskovi za testiranje uredjaja
	SHIFT_F3,	// taskovi za testiranje uredjaja
	SHIFT_F4,	// taskovi za testiranje uredjaja
	SHIFT_F5,	// taskovi za testiranje uredjaja
	SHIFT_F6,	// taskovi za testiranje uredjaja
	SHIFT_F7,	// taskovi za testiranje uredjaja
/*	SHIFT_F8,
	SHIFT_F9,
	SHIFT_F10,	// hotkey za prikaz/brisanje prozora s osnovnim podacima o
						// vozilu u obradi
	SHIFT_F11,
	SHIFT_F12,	// neiskorisceno */

	CTRL_F1,		// spustanje rampe u neregularnim situacijama
	CTRL_F10		// prestanak rezima prioriteta i spustanje rampe
//	CTRL_S,		// hotkey za zahtev za promenu svetla na semaforu namene trake
//	CTRL_V,		//  hotkey za prikaz datuma poslednjih izmena taskova
//	NAJVECI_KOD_SPECIJALNOG_TASTERA_PLUS_1
};


enum KOD_PULSA
{	/* VAZNA NAPOMENA: najmanja vrednost koda aplikativnih pulseva ne sme biti
	 * manja od _PULSE_CODE_MINAVAIL (= 0), a najveca ne sme biti veca od
	 * _PULSE_CODE_MAXAVAIL (=127), kako se ne bi preklapale s vrednostima
	 * sistemskih pulseva. */

	/** pulsevi koje mogu koristiti svi taskovi interno **/
	_INTERNI_PULS_0 /*= _PULSE_CODE_MINAVAIL*/,
	_INTERNI_PULS_1,
	_INTERNI_PULS_2,
	_INTERNI_PULS_3,
	_INTERNI_PULS_4,
	_INTERNI_PULS_5,
	_INTERNI_PULS_6,
	_INTERNI_PULS_7,
//	_INTERNI_PULS_8,	// za preko 8 internih pulseva za sada nema potrebe
//	_INTERNI_PULS_9,
//	_INTERNI_PULS_10,

	// kodovi impulsa zajednicki za vise taskova
	_GRESKA_RAC_APL,	// greska u radu racunara ili aplikacije

	/** Impulsi od taska "tinic" **/
	_TI_,		/* ka "tdistribucija" (vrednosti ...) i "tpromena"  (vrednost je
		 * anomalija/alarm vezana za elektronsku naplatu) */


	/** Impulsi od taska "tkonzola" **/
	_TK_,											// ka "tnaplata"
	_TK_TASTER,	/* njime task TKONZOLA prosledjuje pritisnut taster tasku
		 * TNAPLATA ili tasku za testiranje periferijskog uredjaja, a task
		 * TPROMENA obavestava da je pritisnut taster F11 */
	_TK_OPCIJA,								// ka "tnaplata"
	_TK_PRIKAZ_VOZ_ZA_OBRADU,	// ka "tvozila"
	_TK_AN_PODACI,						// ka "tautonaplata"

	/** Pulsevi od taska TPROMENA **/
	_TPr_,	/* opsti kod pulsa; njime se, izmedju ostalog, od taska TVOZILA
	 * zahteva javljanje o ispraznjenoj traci, od taska TDISTRIBUCIJA da
	 * prekine/nastavi sa izdavanjem kartica, od taska "tautonaplata" da
	 * prekine/nastavi sa automatskom naplatom, a od taska TULIZL da zatvori/
	 * otvori traku */
	_TPr_NOVA_KONFIGURACIJA,	// ka svim taskovima

	/** Pulsevi taska TSTAMPAC **/
	_TS_NOVO_STANjE_STAMPACA,		// ka tasku TPROMENA

	/** Impuls od taska "tprijavljivanje" **/
	_TP_PRIJAVLJIVANJE,				// ka "tulizl", "tpromena" i "tvozila"

	_NAJVECI_KOD_IMPULSA_PLUS_1	// mora se nalaziti na kraju (trenutna vrednost je 107)
};


typedef	enum
{
	/** Poruke svih taskova **/

	// Promena DB 14.04.2009. V2.78 Pocetak (Poruke za nadzor na pocetku,
														//	radi nezavisnog kompajliranja, NE POMERATI)
	//ODG_USPEH = _IO_MAX + 1,	// Da se ne bi preklapali kodovi sistemskih i aplikativnih poruka
	/** Poruke za task "tnadzor" **/
	TNz_PROVERA_KOMUNIKACIJE = /*_IO_MAX +*/ 1,	/* Da se ne bi preklapali kodovi
		 * sistemskih i aplikativnih poruka ( '_IO_MAX' je definisano u
		 * </usr/include/sys/iomsg.h> kao 0x1FF). */
	TNz_PODACI_O_ULASKU_NAPLATI,
	// Promena DB 14.04.2009. V2.78 Kraj

	// Poruka za task konzole
	// VAZNA NAPOMENA:
	// Ne dodavati nijedan kod poruke ispred ovog zbog uskladjenosti ovog
	// koda poruke na razlicitim cvorovima sa razlicitim verzijama aplikacije u
	// kojima se razlikuju ostali kodovi istih poruka!!!
	TK_MARKIRAJUCA_INFORMACIJA,

	/** Poruke za/od vise taskova **/

	ODG_USPEH,
	ODG_GRESKA,
	POD_O_VOZ,		// za "tvozila" od "tkonzola", a u buducnosti i od " tnaplata"
	ODG_NEMA_POD,	/* odgovor na poruku ne sadrzi dodatne podatke (unija
		 * "parametri" je prazna) */


	/** Poruke za task TKONZOLA i odgovori od istog **/

	TK_OTVARANjE_PROZORA,
	TK_ZATVARANjE_PROZORA,
	TK_NASLOV_PROZORA,
	TK_VIDLjIVOST_WIDGETA,
	TK_SETOVANjE_WIDGETA,
	TK_POLOZAJ_WIDGETA,
	TK_ISPIS_TEKSTA,
	TK_DOPISIVANjE_MULTITEKSTA,
	TK_UNOS_TEKSTA,
	TK_ZADAVANjE_BOJE,
	TK_UNOS_POD,
	TK_UNET_POD,
	TK_TIP_KURSORA,
	TK_POZICIJA_KURSORA,	// pozicioniranje kursu tekstualnom polju
	TK_PRIKAZ_ZNAKA,	// dodavanje znaka fokusiranom tekstualnom polju
	TK_BRISANjE_ZNAKA,	// brisanje poslednjeg znaka u fokusiranom tekstualnom polju
	TK_TASTER,
	ODG_TK_TASTER,
	TK_SLANjE_TASTERA,
	TK_IZBOR_OPCIJE,	// zahtevanje izbora opcije iz liste i zadavanje selektovane opcije
	ODG_TK_IZBOR_OPCIJE,// odgovor sa indeksom izabrane opcije iz liste
	TK_DOPISIVANjE_LISTE,
	TK_ZAMENA_REDA_LISTE,
	TK_PROCENAT,		// prikazivanje procenta obradjenosti datoteke
	TK_ISPIS_NA_TERMINAL,	// ispis na zadati terminal u dijalogu
	TK_KOMUNIKACIJA_S_PERIFERIJOM,	// ispis ASCII kodova binarnih podataka koji se salju periferijskom uredjaju i primaju od njega u servisnom rezimu
	TK_PROMENA_NACINA_KODOVANJA_TEKSTA,


	/**	Poruke taska TOCR **/

	TO_KRAJ_TOCR,
	ODG_TO_KRAJ_TOCR,

	/**	Poruke taska TENP **/

	TE_SET_TIME,
	TE_BEACON_RESET,
	TE_TCPIP_CONFIG,
	TE_BEACON_RF_CONFIG,
	TE_BEACON_STATE,
	TE_BEACON_SOFTWARE_VER,
	TE_MANAGE_DSRC,
	TE_RETRIES_CONFIG,
	TE_BST_CONFIG,
	TE_STATION_CONFIG,
	TE_DSRC_KEY_DOWNLOAD,
	TE_DSRC_KEY_ACTIVATE,
	TE_TARIFF_TABLE_CONFIG,
	TE_TARIFF_SCHEME_CONFIG,
	TE_BLACKLIST_CONFIG,
	TE_BLACKLIST_UPDATE,
	TE_RSE_STATUS,
	TE_KRAJ_TENP,
//	TE_SERVIS_TRANS,
	ODG_TE_SET_TIME,
	ODG_TE_BEACON_RESET,
	ODG_TE_TCPIP_CONFIG,
	ODG_TE_BEACON_RF_CONFIG,
	ODG_TE_BEACON_STATE,
	ODG_TE_BEACON_SOFTWARE_VER,
	ODG_TE_MANAGE_DSRC,
	ODG_TE_RETRIES_CONFIG,
	ODG_TE_BST_CONFIG,
	ODG_TE_STATION_CONFIG,
	ODG_TE_DSRC_KEY_DOWNLOAD,
	ODG_TE_DSRC_KEY_ACTIVATE,
	ODG_TE_TARIFF_TABLE_CONFIG,
	ODG_TE_TARIFF_SCHEME_CONFIG,
	ODG_TE_BLACKLIST_CONFIG,
	ODG_TE_BLACKLIST_UPDATE,
	ODG_TE_RSE_STATUS,
	ODG_TE_KRAJ_TENP,

	/** Poruke taska TDISK **/

	TD_READ_DAT,
	TD_WRITE_DAT,
	TD_LEN_OF_DAT,
	TD_CREAT_DAT,
	TD_UNLINK_DAT,
	TD_RENAME_DAT,
	TD_ACCESS_DAT,
	TD_CHSIZE_DAT,
	TD_DSLOG_DAT,
	TD_USLOG_DAT,
	TD_COPY_DAT,
	TD_PURGE_DAT,
	TD_KRAJ_TDISK,
	ODG_TD_READ_DAT,
	ODG_TD_WRITE_DAT,
	ODG_TD_LEN_OF_DAT,
	ODG_TD_CREAT_DAT,
	ODG_TD_UNLINK_DAT,
	ODG_TD_RENAME_DAT,
	ODG_TD_ACCESS_DAT,
	ODG_TD_CHSIZE_DAT,
	ODG_TD_DSLOG_DAT,
	ODG_TD_USLOG_DAT,
	ODG_TD_COPY_DAT,
	ODG_TD_PURGE_DAT,
	ODG_TD_KRAJ_TDISK,


	/*	Poruke taska THOST	*/

	TH_READ_HOST,
	TH_WRITE_HOST,
	TH_KRAJ_THOST,
	ODG_TH_READ_HOST,
	ODG_TH_WRITE_HOST,
	ODG_TH_KRAJ_THOST,


	/** Poruke taska TSTAMPAC **/

	TS_STAMPANjE,


    /** Poruke zahteva tasku TDISTRIBUTER
      *  ( TDISTRIBUCIJA/TNAPLATA -> TDISTRIBUTER  )**/
    ENC_ODZIV,              // Zahtev za odzivom od distributera
    ENC_DAJ_TASTER,         // Zahtev za skeniranje tastera
    ENC_STOP,               // Prekid rada komandi kao sto su: automat.citanje, skeniranje tastera,
    ENC_STAMPAJ,            // Slanje podataka, stampa, enkodiranje i zadrzi karticu u uredjaj
    ENC_STAMPAJ_IZBACI,     // Slanje podataka, stampa, enkodiranje i parcijalno izbaci karticu
    ENC_ENKODOVANJE,        // Slanje podataka, enkodiranje, i zadrzi karticu u uredjaj
    ENC_REENKODOVANJE,      // Enkodiranje sa postojecim podacima
    ENC_CITAJ,              // Aktiviraj automat. citanja - zahtev za preuzimanjem tek po prijemu kartice
    ENC_CITAJ_U_MASINI,     // Citanje vec prisutne kartice
    ENC_IZBACI,             // Parcijalno izbaci karticu iz uredjaja sa cekanjem da se preuzme
    ENC_SAMO_IZBACI,        // Izbaci karticu iz uredjaja sa cekanjem da se preuzme --- !!!
    ENC_PROGUTAJ,           // Povlacenje kartice
    ENC_CITAJ_STOP,         // Provera uredjaja
    ENC_STATUS,             // Zahtev za statusom
    ENC_VERZIJA,             // Zahtev za verzijom
    ENC_PRISUTNOST_KARTICE, // Zahtev za lociranjem kartice ( u  modulu, na ustima ) na bazi opto senzora
    ENC_PROVERI_IZDAVANJE_KARTICE,
    ENC_VERIFIKUJ,          // ???
    ENC_PARKIRAJ,           // Parkiranje kartice
    ENC_PREKINI,            // Prekini zapoceti niz komandi - npr. autom. citanja
    ENC_RESET,              // Softverski reset distributera
    ENC_PRIPREMI_KARTICU,   // Zahtev za povlacenjem i secenjem kartice
// Promena DB 30092008 V2.74 Pocetak (Citanje sa parking mesta)
    ENC_CITAJ_IZ_PARKINGA,			// Koriscenje     ENC_REZERVA_1
// Promena DB 30092008 V2.74 Kraj
    ENC_PROMENA_DUZ, 		// Zahtev za promenu duzine kartice
    ENC_SNIMI_DUZ,   			// Zahtev za snimanje duzine kartice

    ENC_REZERVA_5,

    /** Poruke dogovora taska TDISTRIBUCIJA
      *  ( TDISTRIBUTER -> TDISTRIBUCIJA/TNAPLATA )**/
    ODG_ENC_OK,
    ODG_ENC_ISKLJUCEN,
    ODG_ENC_NEMA_TRAKE,
    ODG_ENC_MALO_TRAKE,
    ODG_ENC_NECITLJIVA,
    ODG_ENC_NENAMAGNETISANA,
    ODG_ENC_NIJE_UPISANA,
    ODG_ENC_ZAGLAVLJENA,                // ALARM - koji glavi
    ODG_ENC_UZEO_KARTICU,
    ODG_ENC_PRITISNUT_TASTER,
    ODG_ENC_RESETOVAN,
    ODG_ENC_RESET_KART_ZAGLAVLJENA,     // ALARM - koji glavi
    ODG_ENC_KARTICA_PROGUTANA,          // Odgovor nakon uspesne operacije citanja sa gutranjem
    ODG_ENC_NEMA_KARTICE,               // Odnosi na "usta" ENC899
    ODG_ENC_KARTICA_IZDATA,             // Odnosi na "usta" ENC899
    ODG_ENC_KARTICA_UNUTRA,             // Odnosi se na prostor citaca u uredjaju
    ODG_ENC_KARTICA_NIJE_UNUTRA,        // Odnosi se na prostor citaca u uredjaju
    ODG_ENC_KARTICA_OCITANA,            //
    ODG_ENC_POGRESNA_KONFIGURACIJA,     //
    ODG_ENC_NEISPRAVNA_KOMANDA,         //
    ODG_ENC_NEPOKRIVEN_SLUCAJ,          // Slucajevi koji nisu pokriveni od strane TKARTICAR-a
    ODG_ENC_ZAUZET,                     // TDISTRIBUTER/TKARTICAR zauzet izvrsavanjem
    ODG_ENC_NEMA_NISTA,                 // Odgovor na izdavanje komande i pri zahtevu
    ODG_ENC_REZERVA_1,
    ODG_ENC_REZERVA_2,
    ODG_ENC_REZERVA_3,
    ODG_ENC_REZERVA_4,
    ODG_ENC_REZERVA_5,

	/** Poruke za task TNAPLATA i odgovori od istog **/

	TN_POCETAK_NAPLATE,	// od taska TPRIJAVLjIVANjE
//V2.36 MDK 25.12.2006., pocetak
//	TN_POD_VOZILA,	// od taska TVOZILA
//V2.36 MDK 25.12.2006., kraj

	/** Poruke za task "tautonaplata" (ima isti indeks procesa kao "tautonaplata")
	 * i odgovori od istog **/

	TAN_AN_PODACI,	// od "tkonzola"
	ODG_TAN_AN_PODACI,

	/** Poruke od taska naplate ka tasku displeja
	 * i odgovor displeja    					**/
	TKD_PORUKA,
	TKD_ODGOVOR,

	/* Poruke od taska "tnaplata" ka tasku "tpost" i odgovor od istog */
	TPo_NAPLATI,
	ODG_TPo_NAPLATI,
	TPo_STORNIRAJ_NAPLATU,
	ODG_TPo_STORNIRAJ_NAPLATU,
	TPo_ODZIV,
	ODG_TPo_ODZIV,
	TPo_KRAJ,
	ODG_TPo_KRAJ,

	/** Komunikacija tautonaplata i task instrukcionog displeja **/
    TID_PORUKA,                     // TAN ---> TID - zahtev za prikaz
    TID_OK,                         // TID ---> TAN -

	/** Poruke za task TPROMENA **/
	TPr_KONFIGURACIJA_SISTEMA,		// od taska TODR
	TPr_POCETNI_BROJEVI_KARTICA,	// od taska TODR

    // *** Poruka za task TTEST_AUTO_DI_NA
    TTA_ZAHTEV,
    TTA_ODGOVOR,

	/** Poruke za task "tkanadzor" ili "tdvr" **/
	TKn_PODACI_O_ULASKU_NAPLATI,

	NAJVECI_KOD_PORUKE_PLUS_1
}	KOD_PORUKE;


typedef enum
{	/* Koristimo vrednosti kodova gresaka pocev od 500, da se ne bi preklapale
	 * sa vrednostima sistemskih kodova gresaka, (iz fajla /usr/include/errno.h,
	 * u opsegu 0-313), a negativne vrednosti ne koristimo zato sto argument
	 * "status" za MsgReply(), preko koga saljemo nase kodove gresaka, prema
	 * preporuci iz Help-a ne bi trebalo da bude negativne vrednosti. */

	/** Kodovi gresaka svih taskova **/
	NEDEFINISANA_GRESKA = 500,
	LOSI_PODACI,	// bar jedan podatak u poruci ima nedozvoljenu vrednost

	/** Kodovi gresaka taska TMENKAN **/
//qwer izbaciti kada proradi nov "tmenkan"
	TMK_NEMA_PID_CHID,	// dati proces nije registrovao parametre kanala

	/** Kodovi gresaka taska TKONZOLA **/
	TK_GRESKA_PRI_ZAKLjUCAVANjU_FB,
	TK_DIJALOG_VEC_KREIRAN,
	TK_WIDGET_NIJE_NADjEN,
	TK_RODITELj_NIJE_NADjEN,
	TK_NIJE_OTVOREN_PROZOR,
	TK_NIJE_ZATVOREN_PROZOR,
	TK_MAX_AKTIVNIH_DIJALOGA,
	TK_NIJE_DAT_FOKUS,
	TK_NIJE_ISPISAN_TEKST,
	TK_WIDGET_NIJE_REALIZOVAN,
	TK_WIDGET_NIJE_OBRISAN,
	TK_GRESKA_MODIFIKACIJE_TEKSTA,
	TK_GRESKA_CITANjA_RESURSA,
	TK_GRESKA_POSTAVLjANjA_RESURSA,
	TK_GRESKA_MULTITEKST_INFO,
// AK V2.36 14.12.2006., pocetak
//	TK_TREPERENjE_VEC_ZADATO,
// AK V2.36 14.12.2006., kraj
	TK_MAX_TREPCUCIH_WIDGETA,
//	TK_NIJE_UNET_TEKST,			// kada se pritisne 'ESC'


	/**	Kodovi gresaka taska TDISK **/
	TD_LOSA_DUZINA,
	TD_KLJUC_NIJE_PRONADJEN,

	/**	Kodovi gresaka taska THOST	**/

	TH_LOSA_DUZINA,
	TH_GRESKA_U_PRENOSU,
	TH_PRENET_FAJL,
	TH_READLISTA_PUNA,
	TH_TMPLISTA_PUNA
}	KOD_GRESKE;

// DR V2.63 18.02.2008., pocetak
enum REZIMI_RADA
{
	AKTIVAN,
	SERVIS_TEST,
	SERVIS_ZATVOREN
};
// DR V2.63 18.02.2008., kraj

typedef	struct
{
	KOD_PORUKE 		kod_poruke;
	INDEKS_PROCESA	od_procesa, za_proces;

	union
	{
		/** Poruka opsteg tipa **/
		char	opsti_pod[ MAX_DUZ_TEKSTA + 1 ];
		int		int_vrednost;

		/** Poruke tasku "tkonzola" i odgovori od istog **/

		struct
		{
			int	ABI_ime_modula;
		}	tk_otvaranje_prozora;

		struct
		{
			int	ABN_ime_modula;
		}	tk_zatvaranje_prozora;

		struct
		{
			int		ABN_ime_modula;
			char	naslov[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_naslov_prozora;

		struct
		{
			int		ABN_ime_widgeta;
			char	selektovana_opcija;
		}	tk_izbor_opcije;

		struct
		{
			char	izabrana_opcija;
		}	odg_tk_izbor_opcije;

		struct
		{
			int	ABN_widget;
		}	tk_unos_teksta;

		struct
		{
			int		ABN_widget;
			char		stanje;
		}	tk_vidljivost_widgeta, tk_setovanje_widgeta;

		struct
		{
			int		ABN_widget;
			short	x, y;
		}	tk_polozaj_widgeta;

		struct
		{
			char		tip;
		}	tk_tip_kursora;

		struct
		{
			unsigned char	pozicija;
		}	tk_pozicija_kursora;

		struct
		{
			int		ABN_ime_widgeta;
			char		tekst[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_ispis_teksta, tk_dopisivanje_liste, tk_ispis_na_terminal;

		struct
		{
			char	naslov[ MAX_DUZ_TEKSTA / 2 + 1 ];
			char	sadrzaj[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_markirajuca_informacija;

		struct
		{
			int		ABN_widget;
			char		resurs_boje[ 25 ];
			int		crvena;
			int		zelena;
			int		plava;
		}	tk_zadavanje_boje;

		struct
		{
			int		ABN_widget;
			char	broj_reda;
			char	sadrzaj[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_zamena_reda_liste;

/*		struct
		{
			int							ABN_widget;
			unsigned short		najvise_redova;
			char						ime_fonta[ MAX_FONT_TAG ];
			uint32_t					atributi_fonta;
			uint32_t					velicina_fonta;
			PgColor_t				boja_teksta;
			PgColor_t				boja_pozadine;
			char						tekst[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_dopisivanje_multiteksta;
*/
		struct
		{
			int		ABN_widget;
			char		blokirajuci,
						tip_unosa,
						najvise_VB_karaktera,
						string[ MAX_DUZ_TEKSTA + 1 ];	/* Ovo je na kraju da bi se
						 * mogao slati samo deo strukture s korisnim sadrzajem. */
		}	tk_unos_pod;

		struct
		{
			unsigned long	izl_modifikatori, izl_taster;
			char					string[ MAX_DUZ_TEKSTA + 1 ];	/* Ovo je na kraju da
				 * bi se mogao slati samo deo strukture s korisnim sadrzajem. */
		}	odg_tk_unet_pod;

		struct
		{
			char	smer_slanja;
			char	tekst[ MAX_DUZ_TEKSTA + 1 ];	// stavljeno je kao poslednja komponenta radi omogucavanja slanja samo korisnog broja bajtova
		}	tk_komunikacija_s_periferijom;

//		struct
//		{
//			int		ABN_ime_widgeta;
//			char	ime_slike[ MAX_DUZ_TEKSTA + 1 ];
//		}	tk_prikaz_slike;

		struct
		{
			char		izvorni_kod[ 35 + 1 ],
						novi_kod[ 35 + 1 ],
						tekst[ MAX_DUZ_TEKSTA + 1 ];
		}	tk_promena_nacina_kodovanja_teksta;


		/** Poruke tasku "tvozila" i odgovori od istog **/

		struct
		{
			short	id_vozila;	// identifikator vozila u sistemu (dodeljuje ga task TVOZILA)
		}	tv_podaci_TAG, tv_link_na_sliku;

		char		obradjenost_voz[ 1 + 5 + 1 ];	/* Niz karaktera kojim se definise
			 * vozilo ciji se svi prikupljeni podaci podaci traze: ako je 1. karakter
			 * '<', oznacava smer pretrazivanja reda vozila od kraja, a ako to
			 * nije slucaj - od pocetka, dok se ostalim, proizvoljnim brojem
			 * karaktera od ukupno 5 (do sada definisanih) zadaje niz stanja
			 * obradjenosti vozila (definisani su u fajlu <tvozila.h> projekta
			 * "tvozila") dozvoljenih za vozilo ciji se podaci traze. */

		struct
		{
			char	taster;
		}	tk_prikaz_znaka, odt_tk_taster;

		struct
		{
			char	serverski_proces;	/* uzima vrednosti tipa  INDEKS_PROCESA
			 * ili -1; ako bi se za tip promenljive uzeo INDEKS_PROCESA,
			 * osim vece duzine, kompajler bi pri poredjenju tretirao promenljivu
			 * kao pozitivnu, verovatno zato sto je najmanja navedena vrednost
			 * tipa INDEKS_PROCESA jednaka 0. */
		}	tk_slanje_tastera;

		struct
		{
			char	procenat;
		}	tk_procenat;


		/** Poruke taska TENP **/

		struct
		{
			unsigned char	userid;
			time_t	utc_time;
			time_t	local_time_offset;
		}	te_set_time;

		struct
		{
			unsigned char	userid;
		}	te_beacon_reset;

		struct
		{
			unsigned char	userid;
			unsigned long	ip_address;
			unsigned long	subnet_mask;
			unsigned long	gateway;
			unsigned short	ccs_port_number;
			unsigned short	dpc_port_number;
		}	te_tcpip_config;

		struct
		{
			unsigned char	userid;
			unsigned char	power;
			unsigned char	channel;
		}	te_beacon_rf_config;

		struct
		{
			unsigned char	userid;
		}	te_beacon_state;

		struct
		{
			unsigned char	userid;
		}	te_beacon_software_ver;

		struct
		{
			unsigned char	userid;
			unsigned char	toggle;
		}	te_manage_dsrc;

		struct
		{
			unsigned char	userid;
			unsigned short	retries_number;
			unsigned char	delay_time;
		}	te_retries_config;

		struct
		{
			unsigned char	userid;
			unsigned short	beacon_mid;
			unsigned long	beacon_iid;
		}	te_bst_config;

		struct
		{
			unsigned char	userid;
			unsigned long	session_service_provider;
			unsigned long	station_location;
			unsigned char	session_location;
			unsigned char	session_type;
		}	te_station_config;

		struct
		{
			unsigned char	userid;
			unsigned char	provider_index;
			unsigned char	dsrckeyid;
			unsigned char	*key;
		}	te_dsrc_key_download;

		struct
		{
			unsigned char	userid;
			unsigned char	provider_index;
			unsigned char	dsrckeyid;
		}	te_dsrc_key_activate;

		struct
		{
			unsigned char			userid;
			unsigned long			tariff_table_ver;
			unsigned short			stationid;
			unsigned long			begin_time;
			unsigned long			end_time;
			unsigned char			number_of_intervals;
			unsigned char			act_intervals;
			struct
			{
				unsigned char	day_of_week;
				unsigned char	begin_time_hour;
				unsigned char	begin_time_mins;
				unsigned char	end_time_hour;
				unsigned char	end_time_mins;
				unsigned char	scheme_number;
			}	table_intervals[31];
		}	te_tariff_table_config;

		struct
		{
			unsigned char		userid;
			unsigned char		number_of_schemes;
			unsigned char		act_schemes;
			unsigned char		schemeid;
			unsigned short		preticket_stationid;
			unsigned short		preticket_validity;
			unsigned short		payment_units;
			unsigned char		number_of_fees;
			unsigned char		act_fees;
			unsigned char		scheme_fees_number;
			struct
			{
				unsigned char	type_of_contract[2];
				unsigned char	vehicle_class;
				unsigned char	emission_class;
				unsigned char	fee[2];
			}	scheme_fees[31];
		}	te_tariff_scheme_config;

		struct
		{
			unsigned char		userid;
			unsigned short		act_id_number;
			unsigned short		max_id_number;
			unsigned short		country_code;
			unsigned short		issueid;
			unsigned short		contract_type;
			unsigned short		mfid;
			unsigned char		bl_records_number;
			struct
			{
				unsigned char	id[4];
				unsigned char	bl_status[2];
			}	*bl_records[17];
		}	te_blacklist_config, te_blacklist_update;

		struct
		{
			unsigned char	userid;
		}	te_rse_status;

		struct
		{
			unsigned char	state;
		}	odg_te_beacon_state;

		struct
		{
			unsigned short	application_ver;
			unsigned char	bootloader_ver;
		}	odg_te_beacon_software_ver;

		struct
		{
			unsigned char	state1;
			unsigned char	validity1;
			unsigned char	schemes1;
			unsigned char	intervals1;
			unsigned long	tariff_table_ver1;
			unsigned long	fee_sum1;
			unsigned char	state2;
			unsigned char	validity2;
			unsigned char	schemes2;
			unsigned char	intervals2;
			unsigned long	tariff_table_ver2;
			unsigned long	fee_sum2;
			unsigned long	bl_number_of_entries;
		}	odg_te_rse_status;


		/**	Poruke taska TSTAMPAC **/

		struct
		{
			char	sadrzaj[ 1024 ];	// Podaci za stampanje menjackog dela priznanice (odbijanje)
		}	ts_stampanje;


		/** Poruka od taska TNAPLATA/TDISTRIBUCIJA ka tasku TVOZILA **/
		struct
		{
			unsigned short id_vozila;	// ID vozila za koji se salje zahtev
		}	tv_zahtev;

		/** Poruka od taska "tnaplata" ka tasku "tpost" **/
		struct
		{
			int		kod_poruke;
			char		podaci[ 79 + 1 ];
		}	tpo_zahtev, odg_tpo_zahtev;


        // *** Zahtev za ispis pri testiranju TAN i TDI
        struct
        {
            char    ind_tip;            // Zahtev, Odgovor,
            char    stanje[ 32 + 1 ];
            char    komanda[ 64 + 1 ];
            char    odgovor[ 64 + 1 ];
            char    tekst[ 128 ];       // Stanje
        }   ttest_di_na_zahtev;

		struct
		{
			char		titl[4*20+1];
		}	tkn_podaci_o_ulasku_naplati, tnz_podaci_o_ulasku_naplati;

		/** Poruke ka tasku "tnadzor" na cvoru "Nadzor" **/
		struct
		{
			char		kod_trake;
			time_t	vreme;		// tekuce vreme u sekundama od 1.1.1970.
			char		komunikacija_host;	// stanje komunikacije datog NUR-a s host-racunarom
		} tnz_provera_komunikacije;
	}	parametri;
}	PORUKA;

#define	VELICINA_ZAGLAVLjA_PORUKE	sizeof( KOD_PORUKE ) + 2 * sizeof( INDEKS_PROCESA )


#endif // OPSTE_H
