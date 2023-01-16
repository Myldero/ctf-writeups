# Beskrivelse
Forslået sværhedsgrad: **Svær**
Haaukins: **Ja**

ZanderDK sagde engang: "Jeg ville ønske, at vi kunne bruge *the big chungus* her".
Jeg har stadig ingen anelse om, hvad han mente.

[Hobc.zip](https://nextcloud.ntp-event.dk:8443/s/bWMq4Ri6DH2GexJ/download/Hobc.zip)

`nc chungus.hkn 1024`

# Analyse
Vi er blevet givet en binary med libc 2.27, samt source-koden for binarien. Jeg starter med at læse source-koden igennem efter fejl.

Programmet spørger efter en ppm image file, og ved at læse `parse_magic` funktionen, kan vi se at den skal starte med bytes `P3` som er filens magic bytes. Formattet af sådan en fil, kan f.eks. læses [her](http://users.csc.calpoly.edu/~akeen/courses/csc101/handouts/assignments/ppmformat.html)
```
P3
[width] [height]
[max_val]
[byte 0] [byte 1] [byte 2] [...]
```
Det er et meget simpelt format, og det kan ses at programmet implementerer det, omend på en lidt sær måde.

I starten af programmet bliver vi givet to pointers: Pointeren til malloc, som vi kan bruge til at leake libc, og pointeren til den første heap chunk, som vi kan bruge til at leake heapen.

Det første jeg lægger mærke til er, at der ikke er noget tjek på `width`, `height`, eller `max_val`, men alligevel når der allokeres et array til at gemme billedets bytes i, er der en begrænsning på størrelsen:
```c
if (image->size > MAX_IMG_SIZE) {
    data = (char*)malloc(MAX_IMG_SIZE+1);
} else {
    data = (char*)malloc(image->size+1);
}
```
Fordi der ikke er noget tjek på, om den størrelse vi giver faktisk er mindre end `MAX_IMG_SIZE`, kan man bare lave et billede, der er større end `MAX_IMG_SIZE = 0x2800`. Så vil den kun allokere `0x2801` bytes, men vi kan skrive efter det, og effektivt overskrive heap metadata.

Derefter bliver der af en eller anden årsag allokeret en chunk af størrelsen `max_val`, som vi styrer, og som der ikke er noget tjek på:
```c
malloc(image->maxval);
```
Til sidst bliver der allokeret en chunk af størrelsen `255`, hvilket er én for lidt, men kan ikke udnyttes, da størrelsen af heap chunks alligevel er rundet op.
Derefter bliver antallet af gange hvert byte-værdi er brugt gemt i den nye allokerede char array. Det kan desuden ses at signed chars fra `data` arrayet bliver brugt til at indekse, så man kan i princippet indekse bagud ved f.eks. at have bytes af værdi `255 = -1` for at ændre data bag ved arrayet. Denne bug fandt jeg dog ikke nogen grund til at udnytte.
```c
char *y = (char*)malloc(255);
for (int i = 0; i < image->size; i++) {
    y[data[i]]++;
}
```
# Exploitation
Det bliver lidt hintet af opgavens navn, men for at exploite dette kan man bruge teknikken House of Force, som virker på alt før libc 2.29, så libc 2.27 er exploitable.

House of Force virker ved først at overskrive størrelsen af top-chunken på heapen. Man kan eventuelt kigge på [how2heap's PoC af den](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_force.c). Normalt vil store allokations, der ikke kan passe inde i den normale heap bliver allokeret separat med mmap, men hvis vi kan ændre størrelsen af top-chunken, og gør den rigtig stor (f.eks. `0xffffffffffffffff`), så vil libc tro, at der er plads til din nye chunk på heapen og derfor allokere den på den normale heap. Normalt vil dette bare føre til en segfault, da hukommelsen der ligger efter heapen højst sandsynligt ikke er allokeret, men hvis vi kender offsettet af f.eks. libc fra heapen, kan vi lave en chunk der lige præcis er stor nok, sådan at den næste chunk vil blive placeret et sted i libc. Her kunne et godt mål være at overskrive `__free_hook`, da programmet kalder `free(y)` inden den lukker. Ved at overskrive `__free_hook` med en pointer til en funktion (f.eks. `system`) vil den kalde `system(y)` før den kører `free`. Derfor hvis vi kan udfylde starten af `y` med `/bin/sh`, vil den kalde `system("/bin/sh")`, og så er der RCE :)

Først bruger jeg [pwninit](https://github.com/io12/pwninit) til at patche binarien til at bruge libc 2.27 i stedet for mit eget systems libc. Her kan man f.eks. også bruge `patchelf --set-interpreter ./ld-2.27.so --replace-needed libc.so.6 ./libc-2.27.so ./hobc`, men det kræver at man selv skal finde `ld-2.27.so`, da den ikke blev givet, hvilket kan være lidt omstændigt.

For at exploite det kan vi lave et billede med størrelse `0x2810 * 1`, og med `max_val` beregnet som offsettet til `__free_hook - 8`. Grunden til at jeg offsetter den med -8 er så jeg kan udfylde `/bin/sh\x00` på de første 8 bytes, efterfulgt af pointeren til `system`. De første `0x2808` bytes udfyldes med tal således, at der er `ord('/')` 0'ere, `ord('b')` 1'ere, `ord('i')` 2'ere, osv. De sidste 8 bytes udfyldes med 255, så topchunken bliver sat til `0xffffffffffffffff`. Se `solve.py` for hele implementeringen af exploiten.

