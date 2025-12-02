# Tiivistelmä: Ohjelmiston suunnittelu ja arkkitehtuuri

## Ohjelmiston suunnittelu
Ohjelmiston suunnittelu jakautuu kahteen päävaiheeseen:

### 1. Arkkitehtuurisuunnittelu
- Määrittelee ohjelman rakenteen **korkealla tasolla**.
- Päätetään, **mistä komponenteista järjestelmä koostuu**, miten ne **kommunikoivat** ja minkälaiset **rajapinnat** niillä on.

### 2. Olio- tai komponenttisuunnittelu
- Keskittyy **yksityiskohtiin**, eli siihen **miten luokat, metodit ja komponentit toteutetaan**.

### Käyttöliittymä- ja käyttökokemussuunnittelu (UI/UX)
- Sijoittuu määrittelyn ja teknisen suunnittelun välimaastoon.
- Kurssin materiaali ei käsittele aihetta syvällisesti.

## Suunnittelun ajoitus ja prosessimallit
### Vesiputousmalli
- Suunnittelu tehdään **kerralla valmiiksi** ennen ohjelmointia.
- Käytännössä harvinainen nykyään.
- **Vaatimusmäärittely ja arkkitehtuurisuunnittelu limittyvät** nykykäytännössä.

### Ketterät menetelmät
- Suunnittelua tehdään **joka sprintissä**, tarpeen mukaan.
- **Laajoja suunnitteludokumentteja ei yleensä tehdä**.

### Big Design Up Front (BDUF)
- Raskas ja tarkka etukäteissuunnittelu.
- Sopii, kun **sovellusalue tunnetaan hyvin** ja **vaatimukset eivät muutu**.

---

# Ohjelmiston arkkitehtuuri

## Arkkitehtuurin käsite
**Software architecture** viittaa järjestelmän keskeiseen rakenteeseen, osien välisiin suhteisiin ja periaatteisiin, jotka ohjaavat järjestelmän **suunnittelua ja evoluutiota**.

### IEEE:n määritelmä
Arkkitehtuuri on järjestelmän **perusorganisaatio**, joka sisältää:
- järjestelmän osat,
- osien keskinäiset suhteet,
- suhteet ympäristöön,
- periaatteet, jotka ohjaavat järjestelmän suunnittelua ja kehitystä.

### Kruchtenin määritelmä
Arkkitehtuuri on **joukko merkittäviä päätöksiä**, jotka koskevat:
- järjestelmän rakennetta,
- sen elementtejä ja rajapintoja,
- elementtien käyttäytymistä ja yhteistyötä,
- elementtien koostamista suuremmiksi kokonaisuuksiksi,
- arkkitehtuurityyliä, joka ohjaa näitä valintoja.

### McGovern ym.
Arkkitehtuuri koostuu **kaikista tärkeistä suunnittelupäätöksistä**, jotka koskevat ohjelmiston rakennetta ja rakenteiden välisiä vuorovaikutuksia.  
Tavoitteena on tukea järjestelmän **laatuominaisuuksia** ja tarjota perusta järjestelmän kehitykselle, käytölle ja ylläpidolle.

---

## Arkkitehtuurin yhteiset teemat
- Määrittelee **järjestelmän rakenteen ja jaottelun osiin**.
- Kuvaa **osien väliset rajapinnat** ja **keskinäisen kommunikoinnin**.
- Sisältää päätökset osien **vastuista ja käyttäytymisestä**.
- Arkkitehtuuri keskittyy **suuriin linjoihin**, ei yksityiskohtiin — se toimii **abstraktiona**.
- Arkkitehtuuri käsittää ne ohjelmiston osat, jotka ovat **vaikeimpia muuttaa** (Martin Fowler).

### Arkkitehtuuriset päätökset
Kruchtenin ilmaisu *set of significant decisions* korostaa, että arkkitehtuuri muodostuu **fundamentaalisista valinnoista**, jotka vaikuttavat sekä ohjelmiston rakenteeseen että toimintaan.  
Nämä päätökset voivat ajan myötä muuttua, mutta niiden **radikaali muuttaminen on yleensä haastavaa**.

---

# Tiivistelmä: Arkkitehtuuriin vaikuttavat tekijät ja arkkitehtuurityylit

## Arkkitehtuuriin vaikuttavat tekijät

### Toiminnalliset ja ei-toiminnalliset vaatimukset
Järjestelmän vaatimukset jakautuvat kahteen luokkaan:
- **Toiminnalliset vaatimukset**: mitä järjestelmän tulee tehdä.
- **Ei-toiminnalliset vaatimukset (laatuvaatimukset, engl. -ilities)**: millainen järjestelmän on oltava.

### Laatuvaatimukset (-ilities)
Nämä vaikuttavat merkittävästi arkkitehtuurin valintoihin. Esimerkkejä:
- **Käytettävyys**: helppokäyttöisyys.
- **Suorituskyky**: kuinka nopeasti järjestelmä toimii.
- **Skaalautuvuus**: kyky palvella kasvavaa käyttäjämäärää.
- **Vikasietoisuus**: toiminnan jatkuminen virhetilanteissa.
- **Tiedon ajantasaisuus**: kuinka reaaliaikaista tieto on.
- **Tietoturva**: suojaus uhkia vastaan.
- **Ylläpidettävyys**: helppous korjata ja kehittää järjestelmää.
- **Laajennettavuus**: kyky lisätä uusia ominaisuuksia.
- **Testattavuus**: järjestelmän testauksen helppous.
- **Hinta** ja **time-to-market** (kuinka nopeasti tuote saadaan markkinoille).

### Laatuvaatimusten ristiriidat
Jotkin vaatimukset ovat usein **ristiriidassa** keskenään, joten arkkitehdin on tehtävä kompromisseja.  
Esim. **hinta** ja **time-to-market** ovat usein vastakkaisia monille muille vaatimuksille.

Useiden kriittisten ominaisuuksien välillä on matemaattisia rajoja:
- **CAP-teoreema**: jaetussa järjestelmässä ei voida samanaikaisesti taata *yhtenäisyyttä (consistency)*, *saatavuutta (availability)* ja *verkkopartitiotoleranssia (partition tolerance)* kaikissa tilanteissa.

### Toteutusteknologiat ja toimintaympäristö
Arkkitehtuuria rajaavat myös:
- käytettävät **teknologiat**, kuten ohjelmistokehykset,
- **integraatiot** olemassa oleviin järjestelmiin,
- **toimintaympäristön vaatimukset**, kuten lääketieteen tai ilmailun tiukat standardit ja säädökset.

### Arkkitehtuurin rooli ja muuttaminen
Arkkitehtuurin tärkein tehtävä on luoda **kehityksen ja ylläpidon puitteet**, joiden avulla järjestelmä pystyy täyttämään sekä toiminnalliset että ei-toiminnalliset vaatimukset myös tulevaisuudessa.

Jos laatuvaatimukset muuttuvat radikaalisti, alkuperäinen arkkitehtuuri voi osoittautua riittämättömäksi.  
Arkkitehtuurin muuttaminen on **kallista ja hankalaa**, mutta joskus välttämätöntä — esim. kun vaaditaan paljon suurempaa skaalautuvuutta.

---

# Arkkitehtuurityylit (architectural styles)

**Arkkitehtuurityyli** tarkoittaa hyväksi havaittua tapaa jäsentää tietyn tyyppisiä ohjelmistojärjestelmiä. Sovelluksissa käytetään usein useiden tyylien yhdistelmiä.

Yleisiä arkkitehtuurityylejä:
- **Kerrosarkkitehtuuri (Layered architecture)**  
  Järjestelmä jaetaan kerroksiin, kuten presentaatio-, logiikka- ja tietokerrokseen.
- **Model-View-Controller (MVC)**  
  Erottaa datan (Model), käyttöliittymän (View) ja sovelluslogiikan (Controller).
- **Pipes-and-Filters**  
  Tietovirta kulkee peräkkäisten "suodattimien" läpi.
- **Client-Server**  
  Asiakas lähettää pyyntöjä palvelimelle.
- **Publish-Subscribe**  
  Julkaisijat lähettävät tapahtumia tilaajille.
- **Event-Driven Architecture**  
  Tapahtumat ohjaavat järjestelmän toimintaa.
- **REST**  
  Arkkitehtuurinen lähestymistapa HTTP-perusteisiin rajapintoihin.
- **Mikropalveluarkkitehtuuri**  
  Järjestelmä koostuu pienistä itsenäisistä palveluista.
- **Palveluperustainen arkkitehtuuri (SOA)**  
  Palvelut muodostavat kokonaisuuden, mutta ovat löyhemmin sidottuja kuin monoliitissa.

Useimpien sovellusten rakenteessa näkyy **useiden tyylien piirteitä** yhtä aikaa.

---

# Tiivistelmä: Kerrosarkkitehtuuri ja arkkitehtuurin kuvaaminen

## Kerrosarkkitehtuuri (layered architecture)

### Perusidea
Kerrosarkkitehtuuri jakaa sovelluksen **käsitteellisiin kerroksiin**, joista kukin:
- suorittaa oman **abstraktiotasonsa tehtävän**, ja  
- käyttää vain **alapuolisen kerroksen palveluja**.

Tyypillinen rakenne:
1. **Presentation layer (käyttöliittymä)** – lähimpänä käyttäjää  
2. **Business layer (sovelluslogiikka)**  
3. **Persistence layer (tallennuskerros)**  
4. **Database / infrastructure layer** – teknisimmät toiminnot

Jokainen kerros muodostaa **loogisen kokonaisuuden** toisiinsa liittyvistä olioista/komponenteista.

### Edut
- **Ylläpidettävyys:** muutokset pysyvät usein yhden kerroksen sisällä.  
  - UI:n muutokset eivät vaikuta tallennuskerrokseen  
  - Tallennusmuutokset eivät vaikuta UI-kerrokseen  
- **Siirrettävyys:** sovelluslogiikan riippumattomuus käyttöliittymästä helpottaa käyttöä useilla alustoilla (web → mobiili).  
- **Uusiokäyttö:** alempien kerrosten palveluja voidaan käyttää muissakin sovelluksissa.  
- **Selkeä ja tuttu malli** kehittäjille.

### Haitat
- Voi johtaa **massiviiseen monoliittiin**, jota on vaikea:
  - laajentaa  
  - skaalata suuriin käyttäjämääriin  

### Kerrosten väliset riippuvuudet
- Riippuvuus on **aina ylhäältä alas**: ylempi kerros **kutsuu** alempaa.  
  - UI → Services → Repositories  
- Alemmat kerrokset eivät kutsu ylempiä kerroksia.  
- Sekä sovelluslogiikka että tallennuskerros voivat käyttää yhteisiä **entities-olioita**.  
  - Tällöin alempi kerros on kooditasolla riippuvainen näistä luokista, vaikka ne kuuluvat loogisesti ylempään kerrokseen.

---

## Arkkitehtuurin kuvaaminen

### Ei ole yhtä yleistä notaatiota
- **UML**: käytetään, mutta ei erityisen suosittu tai käytännöllinen.  
- **Pakkauskaavio**: näyttää riippuvuudet, mutta ei riitä isoihin kokonaisuuksiin.  
- **Komponenttikaavio**: parempi suurille järjestelmille; näyttää komponentit ja niiden *tarjoamat ja käyttämät rajapinnat*.  
- Käytännössä arkkitehtuuri kuvataan usein **epäformaaleilla laatikko–nuoli -kaavioilla**.

### Useita näkökulmia tarvitaan
- **Korkean tason kuvaus**: keskustelun ja vaatimusmäärittelyn tueksi.  
- **Tarkempi kuvaus**: kehittäjille toteutusta ja ylläpitoa varten.

### Hyvän arkkitehtuurikuvauksen sisältö
- Kuvien lisäksi määritellään:
  - komponenttien **vastuut**  
  - komponenttien väliset **rajapinnat**  
  - **kommunikaation muodot**  
- Muuten riski kasvaa, että arkkitehtuuria ei noudateta.

### Arkkitehtuurivalintojen perustelu
Hyödyllinen arkkitehtuurikuvaus **perustelee tehdyt ratkaisut**, koska:
- muutaman vuoden kuluttua kukaan ei ehkä muista, miksi tietyt päätökset tehtiin  
- perustelut tukevat myöhempää kehitystä ja ylläpitoa

---

# Tiivistelmä: Mikropalveluarkkitehtuuri (microservices)

## Miksi mikropalvelut?
Kerrosarkkitehtuuri voi johtaa **monoliittisiin sovelluksiin**, joita on:
- vaikea laajentaa,
- hankala ylläpitää,
- haastava skaalata suurille käyttäjämäärille.

**Mikropalveluarkkitehtuuri** pyrkii ratkaisemaan nämä ongelmat.

---

## Mikropalveluarkkitehtuurin perusidea
Mikropalveluarkkitehtuuri jakaa sovelluksen **useisiin pieniin, verkossa toimiviin, itsenäisiin palveluihin**.  
Nämä palvelut:
- toimivat **irrallaan toisistaan**,  
- kommunikoivat keskenään **verkon kautta**,  
- eivät käytä yhteistä tietokantaa,  
- eivät jaa koodia,  
- eivät kutsu toistensa metodeja suoraan.

Tavoitteena on **löyhä kytkentä** (loose coupling) ja **mahdollisimman suuri itsenäisyys**.

---

## Palvelujen koko ja vastuu
Mikropalvelun tulee hoitaa **vain yksi selkeä toiminnallisuus** ("do one thing well").

Esimerkki verkkokaupan mikropalveluista:
- käyttäjien hallinta  
- tuotteiden suosittelu  
- tuotteiden haku  
- ostoskori  
- maksupalvelu

---

## Edut

### 1. Laajennettavuus
Uusien ominaisuuksien lisääminen onnistuu:
- toteuttamalla uusi mikropalvelu, tai  
- laajentamalla vain sitä palvelua, jota muutos koskee  
→ Ei tarvitse muokata monoliitin kaikkia kerroksia.

### 2. Skaalautuvuus
Palvelut voidaan skaalata **itsenäisesti**.  
Jos yksi mikropalvelu on suorituskyvyn pullonkaula, sitä voidaan ajaa **useita rinnakkain**.

### 3. Tekninen joustavuus
Eri mikropalvelut voivat käyttää:
- eri ohjelmointikieliä  
- eri sovelluskehyksiä  
- eri tietokantoja  

Monoliiteissa tämä on käytännössä mahdotonta.

---

## Yhteenveto
Mikropalveluarkkitehtuuri rakentaa järjestelmän pienistä, itsenäisistä ja verkon yli kommunikoivista palveluista.  
Se parantaa **laajennettavuutta, skaalautuvuutta ja teknistä joustavuutta**, mutta vaatii selkeää palvelurakennetta ja hyvää koordinointia verkon yli tapahtuvassa kommunikoinnissa.

---

# Tiivistelmä: Mikropalveluiden kommunikointi ja haasteet

## Mikropalveluiden kommunikointi

Mikropalvelut kommunikoivat **verkon välityksellä**, ja siihen on kaksi päämallia:

### 1. REST-pohjainen kommunikointi (HTTP)
- Mikropalvelut tarjoavat **REST-rajapinnan**.
- Kommunikointi toimii kuten web-selaimen ja palvelimen välillä.
- Data lähetetään yleensä **JSON-muodossa**.
- Esimerkki: NHL-tilastojen hakeminen REST-rajapinnasta.

### 2. Viestinvälitys (message queue / message bus)
Palvelut **eivät kommunikoi suoraan**, vaan käyttävät välikätenä **viestinvälityspalvelua** (message broker).

Periaatteet:
- Palvelu **julkaisee (publish)** viestin aiheella (topic), esim. `"new_user"`.
- Viestissä on lisäksi **data**, esim. käyttäjätiedot.
- Palvelut **tilaavat (subscribe)** ne aiheet, joista ovat kiinnostuneita.
- Viestinvälityspalvelu välittää viestit oikeille tilaajille.

Edut:
- Palvelut ovat **löyhästi kytkettyjä**.
- Muutokset yhdessä palvelussa eivät vaikuta muihin, kunhan viestien formaatti säilyy.
- Viestinvälitys on **asynkronista**: lähettäjä ei odota vastaanottajan kuittausta.

### Event-driven architecture
Asynkronisia viestejä kutsutaan usein **eventeiksi**, ja tällaista mallia kutsutaan **event-driven-arkkitehtuuriksi**.  
Kaikki event-driven-järjestelmät eivät kuitenkaan ole mikropalveluita (esim. Tkinter-GUI Pythonissa käyttää eventtejä).

---

# Mikropalveluarkkitehtuurin haasteet

### 1. Palvelujen järkevä jakaminen on vaikeaa
Huono jako voi johtaa tilanteeseen, jossa palvelu joutuu kommunikoimaan **kymmenien muiden** kanssa → heikko suorituskyky.

### 2. Testaus ja debuggaus monimutkaistuvat
Usean palvelun, etenkin viestinvälitteisten, kokonaisuutta on vaikeampi:
- testata  
- jäljittää virheitä  

### 3. Käynnistys ja hallinta ovat haastavia
Satojen mikropalvelujen pyörittäminen tuotannossa vaatii:
- pitkälle vietyä **automaatiota**  
- toimivaa **DevOps-kulttuuria**  
- tehokasta **jatkuvaa integraatiota (CI)**

### 4. Konttiteknologian tarve
Mikropalveluissa käytetään usein **konteja (containers)**, erityisesti **Dockeria**:
- Kontti = kevyt “virtuaalikone”, joka suorittaa yhden palvelun.
- Mahdollistaa suuren määrän mikropalveluja yhdelle palvelimelle.
- Tekee jakelusta ja skaalauksesta helpompaa.

---

### Kurssin rajaus
Mikropalveluihin liittyvä konttien ja DevOpsin syvempi käsittely ei mahdu kurssin sisältöön, mutta aiheesta on tarjolla jatkokurssi **DevOps with Docker**.

---

# Tiivistelmä: Arkkitehtuuri ketterissä menetelmissä ja kävelevä luuranko

## Arkkitehtuuri ketterissä menetelmissä

### Ketterien menetelmien perusajatus
Ketterät menetelmät korostavat:
- **toimivan ohjelmiston nopeaa ja jatkuvaa toimitusta**  
  (“early and continuous delivery of valuable software”)
- **usein tapahtuvaa julkaisua** (viikoista kuukausiin)
- **yksinkertaisten suunnitteluratkaisujen suosimista**  
  (“maximize the amount of work not done”).

Tämä voi olla ristiriidassa perinteisen, pitkään kestävän **Big Design Up Front** -arkkitehtuurisuunnittelun kanssa.

---

## Inkrementaalinen arkkitehtuuri

### Perusidea
Arkkitehtuuri:
1. **määritellään projektin alussa riittävällä tasolla**,  
2. **tarkentuu iteraatio kerrallaan**, sitä mukaa kun toiminnallisuutta rakennetaan.

Kerrosarkkitehtuuria ei rakenneta “kerros kerrallaan”, vaan jokaisessa sprintissä toteutetaan:
- **pieni pala jokaista kerrosta**, tarvittavassa laajuudessa.

### Nollasprintti / pre-game
- Monet tiimit aloittavat projektin **nollasprintillä**, jossa luodaan alustava arkkitehtuuri ja backlog.  
- Scrumissa alkuperäinen “pre game” -vaihe poistettiin myöhemmin, ja Ken Schwaber on jopa vastustanut nollasprintin käsitettä.  
→ Käytäntö kuitenkin elää monissa projekteissa.

---

# Kävelevä luuranko (Walking Skeleton)

### Määritelmä (Alistair Coburn)
Walking skeleton on:
- **pieni, end-to-end toimiva**, erittäin kevyt implementaatio järjestelmästä,
- joka **kytkee yhteen kaikki tärkeimmät arkkitehtuurin osat**,
- ei sisällä lopullista toiminnallisuutta, vaan vain “rungon”.

Se toimii:
- **pohjana arkkitehtuurin evoluutiolle**,  
- **pohjana toiminnallisuuden laajentamiselle**,  
- **pysyväksi osaksi tuotantokoodia**, ei kertakäyttöiseksi.

### Tavoite
- Toteuttaa heti alussa (mielellään ensimmäisessä sprintissä) **sovelluksen arkkitehtuurin runko**, eli kerrosten tai komponenttien tynkäversiot ja niiden välinen kommunikointi.
- Kehitys etenee **luurankoa “lihottaen”**: uusi toiminnallisuus lisätään vähitellen tämän rungon ympärille.

### Laatuvaatimukset
- Walking skeleton **ei ole prototyyppi**, vaan:
  - kirjoitetaan **tuotantokoodin laatutasolla**,  
  - sisältää **regressiotestit**,  
  - kasvaa ja kehittyy projektin mukana.

---

## Yhteenveto
Ketterässä kehityksessä arkkitehtuuri ei synny kokonaan etukäteen, vaan **evoluutiona** useiden sprinttien aikana.  
Keskeinen työkaluna toimii **walking skeleton**, joka rakentaa toimivan arkkitehtuurin perustan heti projektin alussa ja mahdollistaa nopean, jatkuvan toiminnallisuuden lisäämisen.

---

# Tiivistelmä: Inkrementaalisen arkkitehtuurin edut ja riskit

## Inkrementaalisen arkkitehtuurin edut

### Yhteinen arkkitehtuurin omistajuus
Ketterissä menetelmissä (esim. Scrum) ei ole erillistä arkkitehdin roolia, vaan **koko tiimi suunnittelee arkkitehtuurin yhdessä**.  
Tämä heijastaa ketterän manifestin periaatetta:

> *“The best architectures, requirements, and designs emerge from self-organizing teams.”*

Edut:
- Kehittäjät **sitoutuvat paremmin** arkkitehtuuriin, jonka he ovat itse luoneet.
- Arkkitehtuuri on **tiimin yhteisomistuksessa**, ei “norsunluutornissa” olevan arkkitehdin määräämä.

### Kevyt dokumentointi
Kun tiimi itse suunnittelee arkkitehtuurin:
- dokumentointi voi olla **kevyt ja epäformaali** (esim. valkotaulun luonnos),
- koska tiimi tuntee arkkitehtuurin jo valmiiksi.

Jos arkkitehtuuri tulee ulkopuolelta, dokumentoinnin täytyy olla raskaampi ja yksityiskohtaisempi.

### Parempi sopeutuvuus muutoksiin
Ketterissä menetelmissä oletetaan, että **parasta arkkitehtuuria ei voida suunnitella alussa**, koska:
- vaatimukset,
- teknologiat,
- ja toimintaympäristö  
muuttuvat ja tarkentuvat vasta projektin aikana.

Siksi arkkitehtuurisia päätöksiä **on järkevää muuttaa**, jos huomataan että aiemmat valinnat eivät enää palvele tarkoitusta.

### Välttää turhaa työtä
Kuten vaatimusmäärittelyssä, myös arkkitehtuurissa ketterät menetelmät pyrkivät:
- välttämään **liian aikaista suunnittelua**,  
- joka myöhemmin osoittautuisi **turhaksi**.

---

# Inkrementaalisen arkkitehtuurin riskit

### Laatu ja kurinalaisuus ovat välttämättömiä
Inkrementaalinen arkkitehtuuri **onnistuu vain**, jos:
- koodin **sisäinen laatu** pidetään korkeana,
- tiimi työskentelee **kurinalaisesti**.

Martin Fowler kuvaa inkrementaalista suunnittelua näin:

> *“The design of the system grows as the system is implemented… In its common usage, incremental design is a disaster.”*

### Vaarana “ad hoc” -päätökset
Usein todellisuudessa:
- aikataulupaineet,  
- kiire,  
- huolimattomuus  
johtavat siihen, että arkkitehtuuri koostuu **satunnaisista taktista päätöksistä**, ei kokonaisuudesta.

Seurauksena syntyy:
- **sisäisesti heikko rakenne**,  
- vaikeasti muutettava koodi,  
- lopulta **“big ball of mud”** — spagettikoodia, jonka ylläpito ja kehitys on erittäin vaikeaa.

---

## Yhteenveto
Inkrementaalinen arkkitehtuuri tuo ketteryyttä, sitoutumista ja muutoskykyä, mutta onnistuu vain, jos tiimi pystyy ylläpitämään **korkean laadun ja arkkitehtuurisen kurinalaisuuden** sprintistä toiseen.

---

# Tiivistelmä: Olio- ja komponenttisuunnittelu, kapselointi ja koheesio

## Olio- ja komponenttisuunnittelu
Arkkitehtuuri antaa ohjelmistolle **rungon**, jota tarkempi suunnittelu täydentää.  
**Olio- ja komponenttisuunnittelu** keskittyy:
- arkkitehtuuristen komponenttien **rajapintoihin**,  
- ohjelman **luokka- ja moduulirakenteeseen**,  
- koodin **sisäiseen laatuun**, ylläpidettävyyteen ja laajennettavuuteen.

Vesiputousmallissa suunnittelu voidaan dokumentoida tarkasti (esim. UML), mutta ketterissä menetelmissä suunnittelu tapahtuu usein **koodin kirjoittamisen yhteydessä**.

---

## Hyvän koodin periaatteet
Ylläpidettävässä ja laajennettavassa koodissa tulisi olla:

- **Selkeä luettavuus**  
- **Vähäiset sivuvaikutukset** muutoksia tehtäessä  
- **Helppo laajennettavuus**: missä kohtaa muutos tehdään, on selvää  
- **Modulaarisuus**: “yhtä asiaa” vastaavat muutokset yhdessä kohdassa  
- **Helppo varmistaa, ettei muutoksilla ole sivuvaikutuksia**

Nämä tavoitteet saavutetaan keskittymällä laatuattribuutteihin:

- **Kapselointi (encapsulation)**
- **Korkea koheesio (cohesion)**
- **Vähäiset riippuvuudet**
- **Toisteettomuus (DRY)**
- **Testattavuus**
- **Selkeys**

Monia näistä toteutetaan **suunnittelumalleilla (design patterns)**, kuten dependency injection ja repository.

---

# Kapselointi
**Kapselointi (encapsulation)** tarkoittaa, että olio piilottaa sisäisen toteutuksensa ja tarjoaa ulospäin vain tarvittavan rajapinnan.

Yleisiä kapseloinnin kohteita:
- olion sisäinen tila  
- käytetty algoritmi  
- olion luomisen tapa  
- komponentin sisäinen rakenne  

Kapselointia tapahtuu myös arkkitehtuuritasolla:
- kerrosarkkitehtuurissa ylemmät kerrokset näkevät vain alempien tarjoamat palvelut  
- mikropalveluissa palvelu tarjoaa vain rajapinnan, ei sisäistä logiikkaa  

---

# Koheesio (cohesion)
Koheesio kuvaa, **kuinka hyvin ohjelmakoodin osa keskittyy yhteen tehtävään**.  
Korkea koheesio = hyvä → helpompi ymmärtää, testata ja muuttaa.

### Koheesio metoditasolla
Huono esimerkki: metodi, joka
- avaa tietokantayhteyden,
- tekee kyselyn,
- rakentaa olioita,
- sulkee yhteyden.

→ Metodi toimii liian monella eri abstraktiotasolla.  
Ratkaisu: **pilkkominen pienempiin metodeihin**, joilla on selkeä ja yhtenäinen vastuu.

### Koheesio luokkatasolla
Periaate: **Single Responsibility Principle (SRP)**  
→ Luokalla saa olla **vain yksi syy muuttua**.

Esimerkki:
- Alkuperäinen `Laskin`-luokka hoiti sekä laskennan että käyttäjäkommunikoinnin → huono koheesio.
- Ratkaisu: siirtää kommunikointi erilliseen `IO`-luokkaan ja injektoida se konstruktorilla (dependency injection).
→ Laskin keskittyy vain laskemiseen.

### Koheesio komponenttitasolla
Koheesio näkyy myös laajemmin:
- React-komponentit tekevät yhtä asiaa (esim. nappi)  
- Redux-store käsittelee vain sovelluksen tilaa  
- Kerrosarkkitehtuurissa kerrokset keskittyvät omaan vastuuseensa  
- Mikropalvelu toteuttaa yhden liiketoiminnallisen toiminnon (esim. maksupalvelu)

---

# Yhteenveto
Olio- ja komponenttisuunnittelun tavoitteena on rakentaa ohjelmisto, joka on:
- **selkeä**,  
- **muutettavissa**,  
- **laajennettavissa**,  
- **testattavissa**.

Keskeisiä periaatteita ovat **kapselointi**, **koheesio**, **vähäiset riippuvuudet**, **toisteettomuus** ja **selkeys** — usein toteutettuna **suunnittelumallien** avulla.

---

# Tiivistelmä: Riippuvuuksien vähäisyys, suunnitteluperiaatteet ja suunnittelumallit

## Riippuvuuksien vähäisyys (low coupling)
**Low coupling** tarkoittaa, että luokilla ja olioilla on **mahdollisimman vähän riippuvuuksia** toisiinsa.  
Tavoite:
- vähentää turhia sidoksia,
- pitää koodi joustavana ja helposti muutettavana.

Keskeinen periaate:
- **Program to an interface, not to an implementation**  
  → Riippuvuuden tulee kohdistua **abstraktioon** (rajapintaan), ei konkreettiseen toteutukseen.  
  (Pythonissa “rajapinta” = joukko metodeja, joiden olemassaoloa riippuvainen koodi odottaa.)

Keino riippuvuuksien vähentämiseen:
- **Riippuvuuksien injektointi (dependency injection)**  
  → Olio saa tarvitsemansa riippuvuudet konstruktorissa tai metodin parametrina, eikä itse luo niitä.

---

# Favor composition over inheritance
**Koostaminen (composition)** = olio käyttää toista oliota osanaan.  
**Perintä (inheritance)** = luokka laajentaa toisen luokan toiminnallisuutta.

Periaate sanoo:  
**Vältä perintää, käytä koostamista aina kun mahdollista.**

Syyt:
- Perintä luo vahvan riippuvuuden aliluokan ja yliluokan välille.
- Perintä johtaa helposti väärään vastuujakoon ja SRP:n rikkomiseen.
- Koostaminen on joustavampaa ja tukee käyttäytymisen vaihtamista **ajoaikana**.

Esimerkki:
- EuriborTili perittynä Tili-luokasta rikkoi SRP:n.  
- Parempi ratkaisu: kapseloida korkolaskenta omiin luokkiinsa (Tasakorko, EuriborKorko) ja antaa Tili-luokalle **korko-olio**.

---

# Static factory method – suunnittelumalli
**Static factory method** = olion luominen hoidetaan luokan staattisen metodin kautta, ei suoraan konstruktorilla.

Hyödyt:
- Piilottaa olion luomisen yksityiskohdat,
- Piilottaa olion todellisen luokan,
- Vähentää riippuvuuksia konkreettisiin tyyppeihin,
- Parantaa kapselointia.

Esimerkki:
```python
Tili.luo_euribor_tili(...)
Tili.luo_maaraaikais_tili(...)

jatka https://ohjelmistotuotanto-hy.github.io/osa4/#riippuvuuksien-v%C3%A4h%C3%A4isyys 