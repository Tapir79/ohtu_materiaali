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
```

# Tiivistelmä: Riippuvuuksien vähäisyys ja “Favour Composition Over Inheritance”

## 1. Riippuvuuksien vähäisyys (Low Coupling)
**Riippuvuuksien vähäisyys** tarkoittaa, että luokat ja oliot ovat mahdollisimman vähän sidoksissa toisiinsa.  
Tavoitteena on:
- helpompi testattavuus  
- pienemmät muutosten vaikutukset  
- selkeämpi rakenne

Low coupling pyrkii **eliminoimaan tarpeettomat riippuvuudet** erityisesti konkreettisista toteutuksista.

### Yhteys Single Responsibility -periaatteeseen
Single responsibility → paljon pieniä luokkia → väistämättä jonkin verran riippuvuuksia.  
Siksi on tärkeää minimoida turhat riippuvuudet ja riippua mieluummin **rajapinnoista** kuin konkreettisista luokista.

---

## 2. Program to an Interface / Depend on Abstractions
Kaksi samansisältöistä periaatetta:

- **Program to an interface, not to an implementation**
- **Depend on abstractions, not concrete implementations**

Tämä tarkoittaa:
- Riippuvuudet pitää kohdistaa siihen, *mitä luokka tekee* (rajapintaan), ei siihen *miten se tekee sen* (toteutus).
- Pythonissa ei ole muodollista interface-tyyppiä → käytetään **duck typing** – riittää, että olio tarjoaa tarvittavat metodit.

---

## 3. Riippuvuuksien injektointi (Dependency Injection)
Riippuvuudet annetaan luokalle esim.
- konstruktorin kautta  
- metodille argumenttina

Tämä mahdollistaa:
- testattavuuden (voi antaa testikohteelle feikkitoteutuksen)
- riippuvuuksien vaihtamisen ilman luokkamuutoksia

Esimerkki: verkkokaupan Varasto, Pankki ja Viitegeneraattori annettiin konstruktorissa.

---

## 4. Favor Composition Over Inheritance
**Periaate:** Suosi koostamista (composition) perinnän sijaan.

### Miksi?
- Perintä luo vahvan ja usein jäykän riippuvuuden perivän ja perittävän luokan välille.
- Jos toiminnallisuus on jaettava useaan “luokkatyyppiin”, perintä johtaa helposti hankalaan luokkahierarkiaan.
- Koostaminen (lähettämällä olio toiselle oliolle) on joustavampaa.

---

Hyödyt:

* selkeä ja luettava syntaksi
* keskitetty logiikka siitä, miten eri tilit rakennetaan
* ei tarvitse muistaa tarkkaa konstruktorikutsua


# Pattern esimerkkejä

## Valo

Tässä esimerkissä havainnollistetaan kolmea suunnittelumallia:
- Static Factory
- Strategy Pattern
- Command Pattern

Kaikki liittyvät valon ohjaamiseen.

---

# Strategy Pattern - tapa käyttää valoa

Strategy-mallissa kapseloidaan vaihtuva toiminnallisuus omaan luokkaansa.

Valon käyttäytyminen voi olla erilaista:
- normaali valo
- himmennettävä valo

```python
class ValoTapa:
    def kayta(self):
        pass


class NormaaliValo(ValoTapa):
    def kayta(self):
        print("Valo on päällä")


class HimmennettavaValo(ValoTapa):
    def kayta(self):
        print("Valo on päällä himmennettynä")

# Valon strategia - Strategia voidaan vaihtaa ajoaikana.
class Valo:
    def __init__(self, tapa):
        self.tapa = tapa

    def sytyta(self):
        self.tapa.kayta()

```

# Static Factory – miten valo luodaan

Static factory vastaa oikean olion luomisesta.

```python
class ValoTehdas:
    @staticmethod
    def luo(tyyppi):
        if tyyppi == "normaali":
            return Valo(NormaaliValo())
        elif tyyppi == "himmennettava":
            return Valo(HimmennettavaValo())
```




# Command Pattern – mitä tehdään valolle

Command-mallissa jokainen komento on oma luokkansa.

```python
class Komento:
    def suorita(self):
        pass


class SytytaKomento(Komento):
    def __init__(self, valo):
        self.valo = valo

    def suorita(self):
        self.valo.sytyta()
```


Koodin käyttäminen. Olion luontilogiikka on keskitetty yhteen paikkaan.
Toiminto (komento) on irrotettu siitä, kuka sitä kutsuu:         

```python
valo_himmea = ValoTehdas.luo("himmennettava")
valo_himmea.sytyta()


valo_normaali = ValoTehdas.luo("normaali")
komento = SytytaKomento(valo_normaali)
komento.suorita()

```

## Yhteenveto

| Malli           | Mitä ratkaisee        |
|-----------------|-----------------------|
| Strategy        | Miten valo toimii     |
| Static Factory  | Miten valo luodaan    |
| Command         | Mitä valolle tehdään  |

---

# Template method   

Template method -suunnittelumallia käytetään, kun
useiden toimintojen suoritus on lähes sama ja eroaa vain
yhdessä tai muutamassa vaiheessa.

## Esimerkki: juoman valmistus

Kaikki juomat valmistetaan näin:
1. Kiehauta vesi
2. Valmista juoma (vaihtelee)
3. Kaada kuppiin

Vain vaihe 2 eroaa.      
Metodi valmista on template method. 

## Abstrakti yliluokka (template method)

```python
from abc import ABC, abstractmethod

class Juoma(ABC):

    def valmista(self):
        self.kiehauta_vesi()
        self.valmista_juoma()
        self.kaada_kuppiin()

    def kiehauta_vesi(self):
        print("Kiehautetaan vesi")

    def kaada_kuppiin(self):
        print("Kaadetaan kuppiin")

    @abstractmethod
    def valmista_juoma(self):
        pass



class Kahvi(Juoma):
    def valmista_juoma(self):
        print("Lisätään kahvijauhe")

class Tee(Juoma):
    def valmista_juoma(self):
        print("Lisätään teepussi")

```

Käyttö:

```pyton
kahvi = Kahvi()
kahvi.valmista()

tee = Tee()
tee.valmista()
```

## Template Method vs Strategy (lyhyesti)

| Template Method            | Strategy                         |
|----------------------------|----------------------------------|
| Perustuu perintään         | Perustuu koostamiseen            |
| Algoritmin runko kiinteä   | Strategia vaihdettavissa          |
| Käyttäytyminen pysyy samana| Käyttäytyminen voi vaihtua ajoaikana |



# Toisteettomuus (DRY – Don’t Repeat Yourself)

Toisteettomuus (redundanssin välttäminen) on keskeinen koodin laatuattribuutti
kapseloinnin, koheesion ja vähäisten riippuvuuksien ohella.

DRY-periaate (Don’t Repeat Yourself) tarkoittaa, että samaa tietoa tai logiikkaa
ei tule ilmaista useaan kertaan järjestelmässä.

---

## Ilmeinen toisteisuus: copypaste

Yleisin toisteisuuden muoto on **copypaste**:
- sama koodinpätkä kopioidaan useaan paikkaan
- usein helppo poistaa funktioiden tai metodien avulla

Copypaste aiheuttaa ongelmia:
- virheen korjaus vaatii muutoksia moneen paikkaan
- muutokset ovat hitaita ja virheherkkiä
- usein merkki heikosta koheesiosta

---

## Hienovaraisempi toisteisuus

Kaikki toisteisuus ei ole ilmeistä.

Monet **suunnittelumallit** (esim. *Template Method*) pyrkivät poistamaan
hienovaraisempaa toistoa, kuten:
- saman suorituslogiikan toistumista eri luokissa
---

## DRY laajemmassa merkityksessä

Kirjassa *The Pragmatic Programmer* DRY määritellään näin:

> **“Every piece of knowledge must have a single, unambiguous, authoritative representation within a system.”**

Tämä tarkoittaa:
- jokaisella tiedolla on **yksi totuuden lähde**
- DRY koskee muutakin kuin koodia

DRY-periaate tulisi ulottaa myös:
- tietokantaskeemaan
- testikoodiin
- konfiguraatioihin
- build-skripteihin

---

## Single authoritative representation

Single authoritative representation tarkoittaa, että:
- tietty tieto tai sääntö on kapseloitu yhteen paikkaan
- muut osat järjestelmää käyttävät sitä epäsuorasti

### Esimerkki: valuutan käsittely

Jos valuutan käsittely:
- on hajallaan monessa paikassa → muutokset vaikeita
- on kapseloitu esim. `Money`-luokkaan → muutokset helppoja

Uuden valuutan lisääminen voi tällöin vaatia vain:
- yhden luokan muokkaamisen

---

## Hyvä vs. paha copypaste

Copypaste ei ole aina automaattisesti huono asia.

### Hyvä copypaste
- nopea prototyyppi
- yksinkertainen sovellus
- refaktorointi ei tuo merkittävää hyötyä

### Huono copypaste
- toistuu monessa paikassa
- vaikeuttaa muutoksia
- kasvattaa monimutkaisuutta ajan myötä

Copypasten poistamisella on myös **hinta**:
- koodi voi muuttua monimutkaisemmaksi
- abstraktiot voivat olla turhia pienessä ohjelmassa

---

## Käytännön nyrkkisääntö

**Three strikes and you refactor**:
- kahdessa paikassa oleva toisto on vielä ok
- kolmas kopio → refaktorointi kannattaa

Tämä auttaa tasapainottamaan:
- koodin selkeyttä
- joustavuutta
- kehitystyön vaivaa

---

## Yhden kappaleen tiivistys

DRY-periaate pyrkii poistamaan sekä ilmeisen että hienovaraisen toisteisuuden
koodista ja koko järjestelmästä. Sen ydinajatus on, että jokaisella tiedolla
tulisi olla yksi selkeä totuuden lähde. Copypaste voi joskus olla hyväksyttävää,
mutta toistuvan logiikan ilmaantuminen useaan paikkaan on merkki refaktoroinnin
tarpeesta.



# Dekoraattori-suunnittelumalli

Dekoraattoria käytetään, kun:
- halutaan lisätä olioon uusia ominaisuuksia
- ominaisuuksia voidaan yhdistellä vapaasti
- perintä johtaisi räjähdysmäiseen luokkamäärään

Ongelma:     
Asiakas haluaa:
- kahvi maidolla
- kahvi sokerilla 
- kahvi maidolla ja sokerilla
- kahvi maidolla, sokerilla ja hintarajoituksella
- ja jatkossa lisää ominaisuuksia...

-> Perinnällä luokkia tulisi valtavasti          
-> Ratkaisu: dekoraattori

### Dekoraattorin perusidea
Dekoraattori:
- sisältää toisen olion
- delegoi kutsut sille
- lisää omaa toiminnallisuutta
---

Jokainen lisäominaisuus on oma luokkansa. 
Ominaisuuksia voi yhdistellä vapaasti. 
Ei tarvita luokkia kuten:
MaitoinenSokerinenBudjettikahvi

## Lähtötilanne: yksinkertainen kahvi

```python
class Kahvi:
    def kuvaus(self):
        return "Kahvi"

    def hinta(self):
        return 2.0

# maito deokraattori
class Maitokahvi:
    def __init__(self, kahvi):
        self.kahvi = kahvi

    def kuvaus(self):
        return self.kahvi.kuvaus() + ", maito"

    def hinta(self):
        return self.kahvi.hinta() + 0.5

# sokeri dekoraattori
class Sokerikahvi:
    def __init__(self, kahvi):
        self.kahvi = kahvi

    def kuvaus(self):
        return self.kahvi.kuvaus() + ", sokeri"

    def hinta(self):
        return self.kahvi.hinta() + 0.2

# budjetti dekoraattori
class Budjettikahvi:
    def __init__(self, kahvi, maksimi):
        self.kahvi = kahvi
        self.maksimi = maksimi

    def kuvaus(self):
        return self.kahvi.kuvaus()

    def hinta(self):
        if self.kahvi.hinta() > self.maksimi:
            raise Exception("Liian kallis kahvi!")
        return self.kahvi.hinta()


perus_kahvi = Kahvi()
kahvi_maidolla = Maitokahvi(perus_kahvi)
kahvi_maidolla_sokerilla = Sokerikahvi(kahvi_maidolla)
kahvi_maidolla_sokerilla_budjetti = Budjettikahvi(kahvi_maidolla_sokerilla , 3.0)

print(kahvi_maidolla_sokerilla_budjetti.kuvaus())
print(kahvi_maidolla_sokerilla_budjetti.hinta())

### Tulostaa 
# Kahvi, maito, sokeri
# 2.7
```


# Rakentaja-suunnittelumalli (Builder)

Rakentaja-mallia käytetään, kun:
- olion luonti koostuu useista vaiheista
- halutaan selkeä ja luonnollinen tapa yhdistellä ominaisuuksia
- konstruktorista ei haluta pitkää ja sekavaa

Tavoitteena rakentaa leipä seuraavasti 

```python
builder = VoileipaRakentaja()

voileipa = builder.juusto().kinkku().tomaatti().valmis()
```

Mitä tässä tapahtuu?

Builder:

- pitää sisällään työn alla olevan olion

jokainen metodi:
- lisää yhden ominaisuuden
- palauttaa uuden rakentajan
- Metodeja voi ketjuttaa (method chaining)
- Rakentaminen muistuttaa luonnollista kieltä
- on immutable
---


## Lähtötilanne: Voileipä

```python
class Voileipa:
    def __init__(self):
        self.taytteet = []

    def lisaa(self, tayte):
        self.taytteet.append(tayte)

    def kuvaus(self):
        return ", ".join(self.taytteet)

class VoileipaRakentaja:
    def __init__(self, voileipa=None):
        self.voileipa = voileipa or Voileipa()

    def juusto(self):
        uusi = VoileipaRakentaja(self.voileipa)
        uusi.voileipa.lisaa("juusto")
        return uusi

    def kinkku(self):
        uusi = VoileipaRakentaja(self.voileipa)
        uusi.voileipa.lisaa("kinkku")
        return uusi

    def tomaatti(self):
        uusi = VoileipaRakentaja(self.voileipa)
        uusi.voileipa.lisaa("tomaatti")
        return uusi

    def valmis(self):
        return self.voileipa
```



# Keskeiset käsitteet tiiviisti

| Käsite | Selitys |
|-------|---------|
| **Low coupling** | Luokat riippuvat mahdollisimman vähän toisistaan. Parantaa joustavuutta. |
| **Single responsibility principle** | Luokalla vain yksi vastuualue. |
| **Program to an interface** | Riipu rajapinnasta, älä toteutuksesta. |
| **Abstraction over implementation** | Käytä abstraktioita (esim. korkostrategia), älä konkreettisia luokkia. |
| **Dependency injection** | Riippuvuudet annetaan konstruktorin tai metodin kautta. |
| **Composition over inheritance** | Suosi koostamista (oliot yhteistyössä), vältä perintäketjuja. |
| **Koheesio (cohesion)** | Kuinka hyvin luokan sisäiset asiat liittyvät toisiinsa. Korkea koheesio = hyvä. |
| **Duck typing (Python)** | “Jos se käyttäytyy kuin ankka, se on ankka.” Riittää, että olio tarjoaa tarvittavat metodit. |
| **Static factory method** | Staattinen tehdasmetodi, joka luo olion ja piilottaa luomislogiikan käyttäjältä. Parantaa kapselointia. |
| **Kapselointi (encapsulation)** | Olion sisäiset toteutusdetaljit piilotetaan ulkopuolelta. |
| **Strategy pattern** | Suunnittelumalli, jossa vaihteleva algoritmi (esim. korkolaskenta) eriytetään omaksi oliokseen ja voidaan vaihtaa ajoaikana. |
| **Command pattern** | Suunnittelumalli, jossa toiminto (komento) kapseloidaan omaksi oliokseen. Mahdollistaa toimintojen irrottamisen kutsujasta, sekä esim. jonotuksen, lokituksen ja perumisen. |
| **Favour composition over inheritance** | Suosi koostamista perinnän sijaan — yhteistyössä toimivat oliot ovat joustavampia kuin laajat luokkahierarkiat. |
| **Koostaminen (composition)** | Olion toiminta muodostetaan käyttämällä muita olioita “osina”. |
| **Dynaaminen käyttäytyminen** | Olion toiminta voidaan muuttaa ohjelman suorituksen aikana, esim. vaihtamalla strategia. |
| **Konstruktori** | Metodi, joka luo luokan ilmentymän. |
| **Mock-olio** | Testauksessa käytettävä korvaava olio, joka jäljittelee riippuvuuden toimintaa. |
| **Vastuunjako (separation of concerns)** | Jokaisella luokalla on selkeä ja yksittäinen vastuualue. |
| **Tehdasluokka** | Luokka (esim. Pankki), joka on vastuussa olioiden luomisesta ja alustamisesta. |


## Suunnittelumallit – vertailu

| Suunnittelumalli | Tyyppi | Mitä ongelmaa ratkaisee | Ydinidea | Tyypillinen esimerkki |
|------------------|--------|--------------------------|----------|------------------------|
| **Strategy** | Käyttäytymismalli | Vaihteleva algoritmi / käyttäytyminen | Algoritmi kapseloidaan omaksi oliokseen ja voidaan vaihtaa ajoaikana | Valon toimintatapa (normaali / himmennettävä) |
| **Command** | Käyttäytymismalli | Toiminnon irrottaminen kutsujasta | Toiminto kapseloidaan omaksi oliokseen | SytytäKomento(valo) |
| **Template Method** | Käyttäytymismalli | Saman algoritmirungon toisto | Yliluokka määrittää rungon, aliluokat vaihtelevat osia | Kahvin vs teen valmistus |
| **Decorator** | Rakennemalli | Ominaisuuksien yhdistely ilman perintäräjähdystä | Olio kääritään toiseen olioon, joka lisää toiminnallisuutta | Kahvi + maito + sokeri |
| **Builder** | Luontimalli | Monivaiheinen ja selkeä olion luonti | Ketjutettavat rakennusvaiheet, lopuksi valmis olio | VoileipäRakentaja |
| **Static Factory Method** | Luontimalli | Olion luontilogiikan piilottaminen | Staattinen metodi luo ja palauttaa olion | ValoTehdas.luo(...) |
| **Factory (Factory Method / Simple Factory)** | Luontimalli | Olioiden luomisen keskittäminen | Erillinen tehdas vastaa luomisesta | Tili-tehdas |
| **Dependency Injection** | Rakennemalli | Tiukat riippuvuudet | Riippuvuudet annetaan olion ulkopuolelta | Pankki annetaan konstruktorissa |
| **Repository** | Rakennemalli | Tietokantariippuvuuksien eristäminen | Data-access kapseloidaan omaan luokkaan | UserRepository |




# Koodin laatu: tiivistetty yhteenveto

## Testattavuus

Hyvän koodin tärkeä ominaisuus on **testattavuus**:
- koodi on helppo testata yksikkö- ja integraatiotesteillä
- seuraa yleensä:
  - selkeästä vastuunjaosta
  - löyhästä kytkennästä
  - vähäisistä riippuvuuksista

Jos koodia on vaikea testata, syy on usein:
- epäselvät vastuut
- liialliset riippuvuudet

-> Testattavuutta parannetaan esim. **riippuvuuksien injektoinnilla**.

---

## Selkeys (Clean Code)

Nykyinen ohjelmointityyli korostaa **luettavuutta ja selkeyttä**:
- koodi kertoo nimien ja rakenteen avulla, mitä se tekee
- tehokkuus ei enää perustu kryptiseen koodiin

Selkeän koodin merkitys:
- jopa ~90 % ajasta kuluu koodin lukemiseen
- koodia luetaan debugatessa ja laajennettaessa
- oma koodi ei ole enää selkeää kuukausien päästä

-> Selkeä koodi auttaa sekä muita että itseä tulevaisuudessa.

---

## Code smell (koodihaju)

**Code smell** on helposti havaittava merkki siitä,
että koodissa voi olla rakenteellinen ongelma.

Se ei ole virhe, vaan **oire huonosta sisäisestä laadusta**.

### Tyypillisiä koodihajuja
- toisteinen koodi
- liian pitkät metodit
- liian suuret luokat
- pitkät parametrilistat
- epäselvät nimet
- kommenttien liikakäyttö

Usein nämä liittyvät:
- huonoon koheesioon
- single responsibility -periaatteen rikkomiseen

### Vähemmän ilmeisiä koodihajuja
- **Primitive obsession**  
  -> käsitteitä (esim. raha, osoite) esitetään primitiivityypeillä
- **Shotgun surgery**  
  -> yhden muutoksen tekeminen vaatii muutoksia monessa paikassa  
  -> merkki huonosta kapseloinnista ja DRY-rikkomuksesta

---

## Refaktorointi

**Refaktorointi** = koodin sisäisen rakenteen parantaminen  
-> **toiminnallisuus ei muutu**

Keskeiset periaatteet:
- tehdään pienin askelin
- testit ajetaan jokaisen muutoksen jälkeen
- testit ovat lähes välttämättömiä

Tyypillisiä refaktorointeja:
- Rename variable/method/class
- Extract method
- Move method/field
- Extract superclass

Monimutkaisemmissa tapauksissa:
- refaktorointi tehdään **suunnittelumallien avulla**
- ks. *Refactoring to Patterns*

Refaktorointia kannattaa tehdä jatkuvasti, jotta:
- koodi pysyy laajennettavana
- tekninen velka ei kasva hallitsemattomaksi

---

## Tekninen velka (Technical Debt)

**Tekninen velka** tarkoittaa huonoa sisäistä laatua,
joka hidastaa kehitystä tulevaisuudessa.

### Tekninen velka voi olla:
- tahatonta (osaamattomuus, tietämättömyys)
- tietoista (aikapaine, MVP)

### Milloin tekninen velka on ok?
- prototyypit
- MVP (Minimal Viable Product)
- markkina- tai rahoituspaine

### Fowler: teknisen velan neljä luokkaa
1. **Reckless & deliberate**  
   “Ei ole aikaa suunnittelulle”
2. **Reckless & inadvertent**  
   “Mikä on arkkitehtuuri?”
3. **Prudent & inadvertent**  
   “Nyt tiedämme miten tämä olisi pitänyt tehdä”
4. **Prudent & deliberate**  
   “Julkaistaan nyt, korjataan myöhemmin”

* Luokat 1–2 = huono velka  
* Luokat 3–4 = harkittu velka

Tekninen velka on kuin laina:
- oikein mitoitettuna hyödyllinen
- hallitsemattomana kehitystä lamauttava
