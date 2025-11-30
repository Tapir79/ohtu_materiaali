# Tiivistelmä: Vaatimusmäärittely

## Mikä on vaatimusmäärittely?
Vaatimusmäärittely (requirements engineering) tarkoittaa asiakkaan vaatimusten selvittämistä, kirjaamista ja hallintaa. Se on yksi ohjelmistotuotannon vaikeimmista ja tärkeimmistä vaiheista.

Vaatimukset jaetaan kahteen luokkaan:
- **Toiminnalliset vaatimukset (functional requirements):** mitä ohjelmistolla voi tehdä (toiminnot, palvelut).
- **Ei-toiminnalliset vaatimukset (non-functional requirements):** laadulliset vaatimukset (esim. käytettävyys, suorituskyky, tietoturva) ja ympäristön asettamat rajoitteet.

Lineaarisissa malleissa (vesiputous) vaatimukset määritellään kokonaan etukäteen.  
Iteratiivisissa malleissa (agile) niitä tarkennetaan vähitellen projektin edetessä.

---

## Vaatimusmäärittelyn vaiheet
Prosessi sisältää tyypillisesti viisi toisiaan täydentävää vaihetta:

1. **Vaatimusten kartoitus (elicitation)** – vaatimusten kerääminen sidosryhmiltä.
2. **Vaatimusten analyysi** – ristiriitojen etsiminen, realistisuuden ja kattavuuden arviointi.
3. **Vaatimusten dokumentointi** – kirjattu kuvaus toiminnallisuudesta ja rajoitteista.
4. **Vaatimusten validointi** – varmistetaan, että dokumentoidut vaatimukset vastaavat asiakkaan todellisia tarpeita.
5. **Vaatimusten hallinnointi** – vaatimusten muutosten ja priorisoinnin hallinta projektin aikana.

Prosessi etenee yleensä **spiraalimaisesti**: vaatimuksia tarkennetaan ja laajennetaan vaiheittain.

---

## Vaatimusten kartoitus – menetelmiä
Ensin tunnistetaan järjestelmän **sidosryhmät** (stakeholders), kuten loppukäyttäjät, tilaaja ja integraatiojärjestelmien ylläpitäjät.

Vaatimuksia kerätään monin keinoin:
- haastattelut
- työpajat / ideointisessiot
- käyttäjäroolien ja käyttöskenaarioiden laadinta
- käyttöliittymäluonnokset ja paperiprototyypit
- etnografia (käyttäjien työn havainnointi)
- nykyisten työprosessien tai järjestelmien analyysi

Nämä auttavat asiakasta täsmentämään tarpeitaan.

---

## Analysointi, dokumentointi ja validointi
### Analyysi:
- poistetaan ristiriidat  
- arvioidaan kattavuus ja toteutettavuus  
- varmistetaan, että vaatimukset ovat **todennettavia**  
  - esim. “järjestelmä on helppokäyttöinen” on huono vaatimus  
  - “uuden käyttäjän tulee suoriutua tehtävästä X alle 2 minuutissa” on hyvä

### Dokumentointi:
- tarvitaan ohjelmoinnin perustaksi  
- tarvitaan testausta varten  
- toimii sopimusmateriaalina (erityisesti vesiputousmallissa)

### Validointi:
- tarkistetaan, että dokumentoidut vaatimukset kuvaavat **oikeasti haluttua järjestelmää**

---

## Vaatimusten hallinta
Vaatimuksia tulee ylläpitää koko projektin ajan:
- uusia vaatimuksia syntyy
- vanhoja tarkennetaan tai poistetaan
- prioriteetit muuttuvat

Hallinnan tavoitteena on pitää vaatimukset ajan tasalla ja selkeinä kaikille.

---

## Yhteenveto
Vaatimusmäärittely on jatkuva prosessi, joka sisältää:
- vaatimusten keräämisen
- analyysin
- dokumentoinnin
- validoinnin
- muutosten hallinnan

Onnistunut vaatimusmäärittely on edellytys toimivalle ohjelmistolle — väärin ymmärretyt tai puutteelliset vaatimukset ovat yksi yleisimmistä ohjelmistoprojektien epäonnistumisen syistä.

# Tiivistelmä: Toiminnalliset ja ei-toiminnalliset vaatimukset

## Toiminnalliset vaatimukset (Functional requirements)
Toiminnalliset vaatimukset kuvaavat *mitä järjestelmällä voi tehdä* — eli sen tarjoamat toiminnot käyttäjän tai toisen järjestelmän näkökulmasta.

### Esimerkkejä toiminnallisista vaatimuksista (verkkokauppa)
- Asiakas voi rekisteröityä käyttäjäksi.
- Rekisteröitynyt asiakas voi lisätä tuotteen ostoskoriin.
- Maksun onnistuessa lähetetään sähköpostivahvistus.
- Kirjautunut asiakas näkee ostohistoriansa.
- Ylläpitäjä voi lisätä uusia tuotteita.
- Tavarantoimittaja voi päivittää hintatietoja.
- Ostotapahtumat synkronoidaan analytiikkajärjestelmään.

### Miten toiminnallisia vaatimuksia kuvataan?
- Feature-listat  
- Use caset (UML)  
- User storyt (ketterät menetelmät)  

Toiminnallisuus ilmaistaan usein käyttäjäroolin kautta, esim.  
*“Tavarantoimittaja voi päivittää tuotteiden hintoja.”*

---

## Ei-toiminnalliset vaatimukset (Non-functional requirements)
Ei-toiminnalliset vaatimukset kuvaavat **järjestelmän laatua** ja **toimintaympäristöön liittyviä rajoitteita**. Ne koskevat yleensä *koko järjestelmää*, eivät yksittäisiä toimintoja.

### 1. Laatuvaatimukset (Quality attributes)
Laadulliset vaatimukset määrittelevät, *miten hyvin* järjestelmän tulee toimia.

Esimerkkejä:
- **Käytettävyys:** sovellus on helppo käyttää.
- **Saavutettavuus:** toimii myös erityisryhmille.
- **Tietoturva:** pääsynhallinta ja datan suojaaminen.
- **Suorituskyky:** vasteajat riittävän nopeat.
- **Skaalautuvuus:** toimii kasvavalla käyttäjämäärällä.
- **Stabiilius:** toipuu virheistä.

Ei-käyttäjän havaitsemia laatuvaatimuksia:
- **Laajennettavuus:** uudet ominaisuudet helppo lisätä.
- **Testattavuus:** virheet löydettävissä helposti.

### 2. Toimintaympäristön rajoitteet (Constraints)
Rajoitteet määrittelevät tekniset ja ympäristöön liittyvät ehdot.

Esimerkkejä:
- **Teknologiat:** ohjelmointikielet, kirjastot, tietokannat.
- **Käyttöympäristö:** selain, mobiili, desktop.
- **Integraatiot:** ulkoiset rajapinnat, kirjautumispalvelut.
- **Lait ja standardit:** esim. GDPR-vaatimukset.

---

## Miksi jaottelu on tärkeä?
- **Toiminnalliset vaatimukset** kertovat, mitä järjestelmä tekee.
- **Ei-toiminnalliset vaatimukset** määrittelevät, millainen järjestelmän tulee olla ja miten se käyttäytyy kuormituksessa, virhetilanteissa tai eri ympäristöissä.

Erityisesti laatuvaatimukset vaikuttavat voimakkaasti **järjestelmän arkkitehtuuriin**. Niiden muuttaminen projektin aikana voi olla hyvin vaikeaa.

# Tiivistelmä: Vaatimusmäärittely vesiputousmallissa

## Vesiputousmallin aikainen vaatimusmäärittely
Vesiputousmallissa vaatimusmäärittely nähtiin **erillisenä, kattavana alkuvaiheena**, joka oli tehtävä kokonaan valmiiksi ennen suunnittelua tai toteutusta.  
Keskeisiä piirteitä:
- Vaatimusten tuli olla **täydellisiä, ristiriidattomia ja kattavia**.
- Tavoitteena oli, että suunnittelu ei vaikuttaisi vaatimuksiin, eikä vaatimukset rajoittaisi suunnittelua.
- Dokumentointi oli erittäin tarkkaa, koska eri henkilöt tekivät määrittelyn ja toteutuksen.
- Joissain suuntauksissa vaatimukset haluttiin ilmaista **formaaleilla kielillä**, jotta niiden virheettömyys voitiin todistaa matemaattisesti.

Perustelut tälle lähestymistavalle:
- Mitä myöhemmin virhe huomataan, sitä kalliimpi sen korjaaminen on.
- Siksi määrittelyvaiheesta tehtiin "järeä" ja erittäin huolellinen.

---

## Miksi vesiputousmainen vaatimusmäärittely ei toimi?
Käytännössä on osoittautunut **utopiaksi** odottaa, että kaikki vaatimukset voidaan määritellä täysin etukäteen.

### 1. Vaatimukset muuttuvat väistämättä
- Asiakkaan toimintaympäristö muuttuu nopeasti.
- Asiakkaat eivät pysty kertomaan kaikkia tarpeitaan etukäteen.
- Asiakkaan mielipide muuttuu nähtyään ensimmäisen version.

### 2. Väärinymmärrykset ovat yleisiä
Ilman jatkuvaa yhteistyötä:
- Kehittäjät tulkitsevat dokumentoituja vaatimuksia eri tavalla kuin asiakkaat tarkoittavat.
- Paperilla selkeä vaatimus toteutuu käytännössä väärin.

### 3. Vaatimuksia ei voi irrottaa suunnittelusta
- Suunnittelu ja tekniset ratkaisut paljastavat uusia tarpeita ja rajoituksia.
- Vaatimusten muotoilu paranee vasta, kun tekninen konkreettisuus tulee mukaan.

### 4. Nykyinen ohjelmistokehitys perustuu valmiisiin komponentteihin
- SaaS-palvelut, open source -kirjastot ja integraatiot vaikuttavat voimakkaasti siihen, **mitä kannattaa vaatia**.
- Jos näitä ei huomioida määrittelyssä, työmäärä kasvaa tarpeettomasti.

### 5. Väärä muotoilu → väärä hinta
Jos suunnittelu ja toteutus eivät vaikuta vaatimuksiin:
- Asiakas voi vaatia jotain, joka on **moninkertaisesti kalliimpi** kuin yhtä hyvä, mutta eri tavalla muotoiltu ratkaisu.
- Ilman teknistä näkökulmaa priorisointi on epärealistista.

---

## Yhteenveto
Vesiputousmallin vaatimusmäärittely yritti olla täydellinen ja muuttumaton, mutta todelliset projektit ovat dynaamisia.  
Siksi vaatimusten eristäminen omaksi vaiheekseen:
- aiheutti paljon väärinymmärryksiä  
- lisäsi kustannuksia  
- hidasti kehitystä  
- ei vastannut muuttuvan ympäristön tarpeita  

Kokemus osoitti, että vaatimusten on **pakko elää**, ja niiden määrittely on tehokkainta *yhdessä suunnittelun ja toteutuksen kanssa*.

# Tiivistelmä: Vaatimusmäärittely iteratiivisessa ja ketterässä kehityksessä

## Perusidea
Ketterässä ja iteratiivisessa ohjelmistokehityksessä vaatimusmäärittelyä **ei tehdä kerralla valmiiksi**, kuten vesiputousmallissa.  
Sen sijaan:
- tehdään **alustava**, suuntaa antava määrittely  
- tarkennetaan vaatimuksia **askel askeleelta** projektin edetessä  
- määrittely, suunnittelu, ohjelmointi ja testaus tehdään jokaisessa iteraatiossa

---

## Vaatimusten priorisointi ja iteraatiot
Ketterissä menetelmissä:
- **asiakas / product owner** priorisoi vaatimukset liiketoiminnallisen arvon perusteella  
- **kehitystiimi** arvioi työmäärän ja päättää, kuinka paljon voidaan toteuttaa sprintissä  
- joka iteraatio tuottaa **valmiita, toimivia ominaisuuksia**

Jokaisen iteraation tuotos toimii lähtökohtana seuraavan iteraation määrittelylle.

---

## Vaatimusten tarkentuminen jatkuvasti
Koska ohjelmisto kasvaa pala kerrallaan:
- vaatimukset **tarkentuvat** projektin aikana  
- suunnittelu ja toteutus voivat paljastaa uusia tarpeita  
- prosessi on luonnostaan joustava muutoksille

---

## Julkaisu ennen valmista tuotetta
Ketterä kehitys mahdollistaa sen, että:
- sovellus voidaan julkaista **osissa**, jo ennen projektin valmistumista  
- todelliset käyttäjät voivat antaa palautetta  
- palautteen avulla voidaan **tarkentaa vaatimuksia** ja kehityksen suuntaa  
- sovellus voi tuottaa **arvoa** jo kehityksen aikana

---

## Ketterän vaatimusmäärittelyn ydin
Kokonaisuutena ketterä vaatimusmäärittely pyrkii:
- maksimoimaan asiakkaalle tuotettavan arvon  
- mahdollistamaan nopean reagoinnin muutoksiin  
- ohjaamaan kehitystä todellisen käytön ja palautteen perusteella  

Ketteryyden filosofiana on:  
**"Tee tärkein ensin, toimita usein, opi käyttäjiltä ja mukauta."**

# Tiivistelmä: Lean Startup ja uuden ajan vaatimusmäärittely

## Mikä Lean Startup on?
Eric Riesin *The Lean Startup* (2011) esittelee mallin, joka auttaa määrittelemään vaatimuksia **epävarmoissa tilanteissa**, kuten startup-yritysten tuotekehityksessä.  
Keskeinen idea: **vaatimuksia ei voi tietää etukäteen – ne on opittava käytännöstä.**

---

## Build–Measure–Learn -sykli
Lean Startup perustuu jatkuvaan kokeiluun:

1. **Build** – rakennetaan nopeasti kokeilu tai prototyyppi (MVP).
2. **Measure** – mitataan käyttäjien todellista toimintaa.
3. **Learn** – opitaan, toimiko idea vai ei.

Sykliä toistetaan, kunnes löydetään oikeat vaatimukset ja tuote, jota käyttäjät haluavat.

---

## Hypoteesilähtöinen kehitys
Koska käyttäjistä ei vielä tiedetä mitään:
- tehdään **oletus (hypoteesi)** mitä käyttäjät haluavat  
- rakennetaan sen pohjalta pienin mahdollinen toimiva ratkaisu  

Hypoteesia testataan todellisessa käytössä, ei arvailuilla.

---

## MVP – Minimum Viable Product
MVP on **minimaalinen toimiva versio** tuotteesta tai ominaisuudesta.

Tarkoitus:
- saada **mahdollisimman nopeasti palautetta**
- testata idean toimivuutta ilman täyttä toteutusta
- säästää aikaa ja rahaa

MVP ei ole täydellinen, vaan sisältää vain sen, mikä on hypoteesin testaamiseksi välttämätöntä.

---

## Mittaaminen käytännössä
Lean Startup hyödyntää dataa oikeasta käytöstä, esim.:
- rekisteröityneiden käyttäjien määrä
- palaavat käyttäjät
- maksavien asiakkaiden osuus
- käyttöprosentti uuden ominaisuuden kohdalla

Uusia ominaisuuksia verrataan usein **A/B-testauksella**, jossa uusi versio näytetään vain osalle käyttäjistä.

---

## Oppiminen ja päätökset
Mittauksen jälkeen verrataan tuloksia alkuperäiseen hypoteesiin:

- Jos idea **toimii**, MVP:n tilalle tehdään kunnollinen toteutus.
- Jos ei toimi, palataan taaksepäin ja kokeillaan uutta ideaa.

Menetelmä on siis jatkuvaa **oppimista vaatimuksista** todellisen käyttäjäkäyttäytymisen kautta.

---

## Miksi Lean Startup on vaatimusmäärittelyä?
Lean Startup on luonteeltaan:
- **vaatimusten kartoittamista** (mitä käyttäjät todella haluavat?)  
- **validointia** (toimiiko idea käytännössä?)  
- **analysointia** (tuottaako ominaisuus arvoa?)  

Se on “moderni vaatimusmäärittelyprosessi”, joka perustuu dataan eikä oletuksiin.

---

## Käyttö yrityksissä
Vaikka nimi viittaa startupeihin, Lean Startup -mallia käyttävät laajalti:
- Facebook  
- Google  
- Netflix  
- Amazon  
- peliyhtiöt (mm. pelien koukuttavuuden optimointi)

Menetelmä kukoistaa erityisesti internet- ja mobiilipalveluissa, joissa dataa voidaan kerätä nopeasti.


# Tiivistelmä: Vaatimusmäärittely ja projektisuunnittelu ketterässä prosessimallissa

Tämä tiivistelmä kokoaa yhteen keskeiset käsitteet ja käytännöt, joita käytetään ketterässä vaatimusmäärittelyssä sekä projektin suunnittelussa Scrum- ja XP-menetelmien hengessä.

---

## 1. User Story – ketterän vaatimusmäärittelyn perusyksikkö
**User story (käyttäjätarina)** kuvaa asiakkaalle arvoa tuottavan toiminnallisuuden lyhyesti.  
Mike Cohnin määritelmä: story muodostuu kolmesta osasta:

1. **Card** – lyhyt tekstikuvaus (“placeholder”)  
2. **Conversation** – keskustelua asiakkaan ja tiimin välillä toiminnallisuuden tarkentamiseksi  
3. **Confirmation** – hyväksymiskriteerit (testit), joilla valmis story todetaan valmiiksi  

Esimerkkejä:
- “Asiakas voi lisätä tuotteen ostoskoriin”
- “Asiakas voi maksaa ostokset luottokortilla”

User story *ei* ole täydellinen vaatimusdokumentti, vaan muistilappu, jonka yksityiskohdat selvennetään ennen toteutusta.

---

## 2. Hyvän user storyn kriteerit – INVEST
Bill Waken **INVEST**-malli määrittelee, millainen on hyvä, toteutettava user story:

- **I – Independent**: mahdollisimman riippumaton muista storyistä  
- **N – Negotiable**: ei tiukka vaatimusdokumentti, vaan neuvoteltavissa  
- **V – Valuable**: tuottaa arvoa käyttäjälle  
- **E – Estimable**: työmäärä pystytään arvioimaan  
- **S – Small**: mahtuu yhteen sprinttiin  
- **T – Testable**: hyväksymiskriteerit voidaan todentaa  

INVEST koskee ennen kaikkea *korkean prioriteetin storyja*.  
Isot ja epämääräiset storyt ovat **epicejä**, jotka pilkotaan pieniin ennen toteutusta.

---

## 3. Product Backlog – priorisoitu user storyjen lista
**Product backlog** sisältää kaikki kehitysideat ja vaatimukset user storyinä.  
Ominaisuudet:

- **Priorisoitu** (arvo, työmäärä, riskit, ROI)
- **Estimoitu** (yleensä story point -yksiköillä)
- **Elävä** (muuttuu jatkuvasti)
- **Sopivan tarkka** (DEEP-malli)

### Backlog on DEEP
Hyvä backlog on:

- **D – Detailed appropriately**: kärki tarkka, häntä karkea  
- **E – Estimated**: storyt on arvioitu  
- **E – Emergent**: kehittyy jatkuvasti  
- **P – Prioritized**: tärkeimmät ensin  

---

## 4. Estimointi – työmäärän arviointi
Ketterässä kehityksessä estimointia käytetään:

1. **Priorisointiin**  
2. **Projektin keston arviointiin** (epätarkasti)

### Story point
Abstrakti yksikkö, joka **ei vastaa tunteja**.  
Esim. Fibonacci-sarja: 1,2,3,5,8,13…

Tärkeämpää on **tehtävien suhteellinen koko** (mitä isompi epävarmuus, sitä karkeampi arvo).

### Planning Poker
Menetelmä, jossa koko tiimi arvioi storyn koon samanaikaisesti korteilla →  
hyvä keskustelu, yhteinen ymmärrys, läpinäkyvyys.

---

## 5. Velositeetti (Velocity)
**Velositeetti = story pointien määrä, jonka tiimi saa valmiiksi sprintissä.**

Mahdollistaa karkean ennustamisen:
`aika ≈ (kaikkien storyjen pisteet) / (velositeetti)`


Velositeetti:
- vakiintuu muutaman sprintin jälkeen
- ei ole vertailukelpoinen eri tiimien välillä (story pointit eri mittaisia)

---

## 6. Burndown ja Burnup
Visualisointityökaluja etenemisen seuraamiseen:

- **Burndown**: paljonko *työtä on jäljellä*
- **Burnup**: paljonko *työtä on tehty* ja miten työmäärä muuttuu

Burnup tekee vaatimusten lisäykset näkyviksi paremmin.

---

## 7. Sprintin suunnittelu
Sprintin alussa tiimi:

1. valitsee sprinttiin priorisoituja user storyja  
2. varmistaa, että ymmärrys hyväksymiskriteereistä on yhteinen  
3. pilkkoo storyt **taskeiksi** (teknisiksi työvaiheiksi)

---

## 8. Sprint Goal – sprintin tavoite
Lyhyt yleistavoite sprintille, esim.:

- “Ostoskorin perustoiminnallisuus”
- “Maksamisen toteuttaminen”

Sprintin onnistumista arvioidaan tavoitteen, ei pelkästään storyjen, mukaan.

---

## 9. Sprint Backlog ja Taskboard
**Sprint backlog** = sprinttiin valitut user storyt + niiden taskit.

Visuaalinen toteutus (taskboard):
`Not started | In progress | Testing | Done` 


Usein yhdistetään **daily scrumiin**.  
Manuaalinen post-it -taskboard on usein informatiivisin.

---

## 10. Task-estimointi ja burndown sprintin sisällä
Kiistanalainen aihe.  
Vanha Scrum ohjeisti seuraamaan tuntiarvioita → sprint-burndown.

Uudempi ajattelu (Scrum Guide 2020 ja "A Scrum Book"):

- keskity **valmiisiin storyihin**, ei tunteihin
- tunti-estimointi helposti johtaa väärään optimointiin  
  (tehdään paljon puolivalmista työtä)

---

## 11. Storyjen jakaminen (splitting)
Storyt jaetaan pieniin INVEST-kelpoisiin osiin. Tekniikoita:

- **Business rule variations**  
- **Simple / complex**  
- **One example first (major effort)**  
- **Different UI-tasot**  
- **Performance split**  
- **Operations split (CRUD)**  
- **Spike** – kokeilutoteutus riskin selvittämiseksi

Spike muistuttaa Lean Startup -mallin MVP-konseptia.

---

## 12. WIP-rajoitukset ja Scrumban
**WIP (Work In Progress)** = rajataan yhtä aikaa työn alla olevien töiden määrä.  
Hyöty:

- vähentää keskeneräistä työtä (Lean: waste → muda)
- nopeuttaa kokonaisuuksien valmistumista
- ehkäisee ruuhkautumista

Scrumban = Scrumin ja Kanbanin hybridimalli, jossa käytetään mm.

- WIP-rajauksia
- jatkuvaa virtausta (flow)
- taskboardia ilman sprinttejä (tai sprintit + WIP yhdessä)

---

## 13. Release planning ja roadmap
Backlog ei anna riittävää kuvaa pitkän aikavälin suunnitelmista.  
Siksi käytetään:

- **Milestoneja / releaset** (sisältävät useita sprinttejä)
- **Roadmapia** (korkean tason aikajana)

Esim.:

- Release 1: perustoiminnot  
- Release 2: tuotearvostelut  
- Release 3: suosittelualgoritmi

---

## 14. User Story Mapping
Parempi tapa nähdä kokonaisuudet kuin lineaarinen backlog.

Storyt järjestetään *toiminnallisiin kokonaisuuksiin*, esim. verkkokauppa:

- Product search
- Product page
- Checkout

Kussakin sarakkeessa storyt tärkeysjärjestyksessä →  
helppo nähdä mitä sisältyy ensimmäiseen julkaisuun.

---

## 15. #NoEstimates – Estimoinnin kritiikki
Liike, joka kyseenalaistaa story point -estimoinnin hyötyjen suhteen:

- estimointi vie aikaa  
- on epätarkkaa  
- voi ohjata väärään optimointiin  

Vaihtoehtoja:
- mitataan pelkkien valmiiden storyjen lukumäärää sprintissä  
- käytetään samankokoisia storyja → ennustettavuus paranee ilman pisteitä

---

# Yhteenveto

Ketterä vaatimusmäärittely ja suunnittelu perustuvat:

- **User storyihin (card–conversation–confirmation)**
- **Elävään, priorisoituun backlogiin (DEEP)**
- **Suhteelliseen estimointiin (story point, velocity)**
- **Pieniin ja testattaviin storyihin (INVEST)**
- **Iteratiiviseen sprinttisuunnitteluun**
- **Taskboardeihin ja läpinäkyvyyteen**
- **Lean-ajatteluun (vähemmän keskeneräistä työtä)**
- **Jatkuvaan mukautumiseen, oppimiseen ja priorisointiin**

Nämä yhdessä muodostavat joustavan ja liiketoiminta-arvoa korostavan mallin ohjelmistokehityksen projektisuunnitteluun.

