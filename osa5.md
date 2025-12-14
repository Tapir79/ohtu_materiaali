## Lean – tiivistetty yhteenveto

### Tausta
- **Lean** on peräisin **Toyotan tuotanto- ja tuotekehitysmenetelmistä** (1900-luvun alkupuoli).
- Toisen maailmansodan jälkeen Japanissa resurssit olivat niukat →  
  **laadun parantaminen nähtiin tuottavuuden avaimena**.
- Toyota kehitti **Just In Time (JIT)** -mallin:
  - tuotanto alkaa vasta tilauksesta
  - pyritään **lyhyeen läpimenoaikaan (lead time)**
  - vastakohta massatuotannolle ja varastojen keräämiselle

### Keskeiset havainnot Toyotalla
- Laatuongelmat havaitaan nopeasti, kun varastoja ei ole
- Asiakkaiden muuttuviin tarpeisiin on helpompi reagoida
- Optimoidaan **kokonaisvirtausta (flow)**, ei yksittäisten koneiden käyttöastetta
- Kaikki **hukkaa (waste)** aiheuttava poistetaan
- Ongelmiin puututaan heti

### Ihmiskeskeinen kulttuuri
- Työntekijöitä **kunnioitetaan ja vastuullistetaan**
- Jokaisella on oikeus (ja velvollisuus) pysäyttää tuotanto ongelman ilmetessä
- **Jatkuva parantaminen** kuuluu kaikille, ei vain johdolle

---

## Toyota Production System (TPS)
- Nimi käytössä Toyotalla vuodesta **1965**
- Länsimaissa tunnetuksi 1980–90-luvuilla
- Käsite **Lean** vakiintui MIT:n tutkimusten ja kirjan  
  *The Machine That Changed the World* (1990) myötä
- Tunnettu teos: **The Toyota Way** (Jeffrey Liker, 2001)

---

## Lean laajemmassa käytössä
- Alun perin **tuotannon optimointiin**
- Myöhemmin myös:
  - tuotekehitys
  - ohjelmistokehitys (*Lean Software Development*, 2003)
- Vaikuttanut mm. **Scrumiin**
- Nykyään käytössä monilla aloilla:
  - terveydenhuolto
  - pankkitoiminta
  - julkishallinto
- Käsite on laajentunut → “lean” tarkoittaa eri asioita eri yhteyksissä

---

## Leanin perusrakenne (Lean Thinking House)

### Tavoite (Goal)
- **Nopea ja kestävä eteneminen ideasta asiakkaalle**
- Korkea laatu ja asiakastyytyväisyys
- Ei perustu työntekijöiden tai kumppaneiden hyväksikäyttöön

### Perusta (Foundation)
- Pitkän aikavälin ajattelu
- Lean-ajattelun tulee olla **juurtunut koko organisaatioon**
- Johto opettaa ja elää leania esimerkillään

### Kaksi peruspilaria
1. **Jatkuva parantaminen (Continuous Improvement)**
   - Tyytymättömyys nykytilaan
   - Jatkuva kysymys: *“Miksi teemme tämän näin?”*
   - Oppiminen ja kokeileminen keskiössä

2. **Ihmisten kunnioittaminen (Respect for People)**
   - Kuunteleminen ja vastuuttaminen
   - Mentorointi ja turvallinen työympäristö
   - Koskee myös:
     - alihankkijoita (aidot kumppanuudet)
     - asiakkaita

### Työkalut
- Lean ei ole vain työkaluja, mutta niitä tukee mm.
  - **Kanban**
- Työkalut palvelevat periaatteita, eivät korvaa niitä

---

## Kappaleen tiivistys
Lean on Toyotan tuotantojärjestelmästä syntynyt ajattelutapa, jonka tavoitteena on nopea ja laadukas arvon tuottaminen asiakkaalle poistamalla hukkaa, lyhentämällä läpimenoaikaa ja kehittämällä toimintaa jatkuvasti. Lean perustuu kahteen peruspilariin: jatkuvaan parantamiseen ja ihmisten kunnioittamiseen, ja sen onnistuminen edellyttää pitkäjänteistä, koko organisaation kattavaa kulttuuria.


## Jatkuva parantaminen – arvo ja hukka (Lean, tiivistelmä)

### Perusajatus (Taiichi Ohno)
Lean pyrkii **lyhentämään aikaa asiakkaan tilauksesta maksun saamiseen**  
-> tämä tehdään **poistamalla arvoa tuottamaton työ (hukka)**.

- **Arvo (value)**: työvaiheet, joista asiakas on valmis maksamaan  
- **Hukka (waste)**: kaikki työ, joka ei tuota arvoa asiakkaalle

---

## Leanin kolme hukan tyyppiä
Lean tunnistaa kolme hukan pääluokkaa:
- **Muda** – suora arvoa tuottamaton työ (selkein ja yleisin)
- **Mura** – epätasaisuus ja epäyhtenäisyys
- **Muri** – ylikuormitus ja mahdottomat vaatimukset

---

## Muda – 7 klassista hukan muotoa (ohjelmistokehityksen näkökulmasta)

1. **Ylituotanto (Overproduction)**  
   - Turhat ominaisuudet, joita asiakas ei käytä  
   - Lisää kustannuksia ja monimutkaisuutta

2. **Välivarastointi (In-process inventory)**  
   - Keskeneräinen työ, käyttämätön koodi, testaamaton toiminnallisuus  
   - Pitää virheet piilossa ja hidastaa läpivirtausta

3. **Liikatyö (Over/extra processing)**  
   - Ylisuunnittelu, tarpeettomat dokumentit, näennäisesti hyödyttömät testit  
   - Myös “liian hyvä” laatu väärässä vaiheessa (esim. MVP)

4. **Tarpeeton siirtely (Transportation)**  
   - Työn siirtäminen tiimiltä toiselle (handoffit)  
   - Esim. erillinen QA-tiimi testaa muiden tekemää koodia

5. **Tarpeeton liikkuminen (Motion)**  
   - Task switching, työskentely liian monessa asiassa yhtä aikaa

6. **Odotus (Waiting)**  
   - Odotetaan hyväksyntää, testausta, deployta, PR:n mergeä

7. **Viat (Defects)**  
   - Virheet, jotka havaitaan myöhään  
   - Korjaaminen kallista → laatu kannattaa varmistaa aikaisin

### Lisätty muda-tyyppi (myöhemmin)
- **Ihmisten potentiaalin alihyödyntäminen**  
  → osaamista, ideoita ja näkemyksiä ei hyödynnetä

---

## Mura – epätasaisuus
- Epäsäännöllisyys työssä tai tuotteessa
- Esimerkki ohjelmistokehityksessä:
  - hyvin eri kokoiset user storyt
- Seurauksena usein:
  - muda-hukkaa (esim. jonot, keskeneräinen työ)
  - heikko arvon virtaus

---

## Muri – ylikuormitus
- Liialliset tai mahdottomat vaatimukset
- Esimerkkejä:
  - jatkuva kiire
  - henkilöstön ylikuormitus
- Seurauksena usein:
  - virheitä (muda)
  - heikentynyt laatu ja työhyvinvointi

---

## Yhden kappaleen tiivistys
Leanissa jatkuva parantaminen perustuu arvoa tuottamattoman työn poistamiseen. Hukka jaetaan kolmeen tyyppiin: muda (suora hukka), mura (epätasaisuus) ja muri (ylikuormitus). Erityisesti ohjelmistokehityksessä hukkaa syntyy turhista ominaisuuksista, keskeneräisestä työstä, handoffeista, odottamisesta ja virheistä. Tavoitteena on sujuva arvon virtaus asiakkaalle mahdollisimman nopeasti ja laadukkaasti.

## Kaizen – jatkuva parantaminen 

### Mitä kaizen tarkoittaa?
**Kaizen** on jatkuvan parantamisen filosofia, joka kuuluu Lean-ajattelun ytimeen.  
Se koskee **kaikkia työntekijöitä** ja kaikkea tekemistä.

Ajattelutapana kaizen tarkoittaa:
> *“My work is to do my work and to improve my work.”*  
-> Työtä ei vain tehdä, vaan sitä **parannetaan jatkuvasti**, myös ilman ulkoista pakkoa.

---

## Kaizen käytännössä – jatkuva sykli
Kaizen ei ole yksittäinen muutos, vaan **loputon parannussykli**:

1. Valitaan jokin työskentelytapa tai tekniikka  
2. Sitoudutaan käyttämään sitä jonkin aikaa  
3. Kun toiminta on vakiintunut:
   - arvioidaan, mikä toimii ja mikä ei  
   - parannetaan havaittuja epäkohtia  
4. Luodaan uusi, parempi **standarditapa**  
5. Toistetaan sykli uudelleen

-> Pienet, jatkuvat parannukset ovat arvokkaampia kuin harvinaiset suuret mullistukset.

---

## Kaizen eventit
Kaizeniin liittyy usein säännöllisiä pysähtymishetkiä, joissa toimintaa arvioidaan.

- Näitä kutsutaan **kaizen eventeiksi**
- **Scrumin retrospektiivit** ovat klassinen esimerkki:
  - tiimi pohtii, mikä meni hyvin
  - mikä meni huonosti
  - mitä parannetaan seuraavaksi

---

## Lean-työkalu: Value Stream Mapping
**Value stream mapping** auttaa löytämään hukkaa.

Tarkoitus:
- kuvata tuotteen (esim. user storyn) kulku prosessin läpi
- erottaa:
  - arvoa tuottava työ
  - odotukset, jonot ja välivarastot (hukka)

Keskeinen havainto:
- arvo syntyy vain työvaiheissa
- suurin osa ajasta kuluu usein **odottamiseen**

-> Visualisointi auttaa kohdistamaan parannukset oikeisiin kohtiin.

---

## Lean-työkalu: Five Whys (perimmäisen syyn analyysi)
Kaizen ei pyri korjaamaan oireita, vaan **perimmäisiä syitä**.

**Five Whys** -menetelmä:
- kysytään *miksi?* toistuvasti (noin 5 kertaa)
- kunnes päästään juurisyyn tasolle

### Kysymykset: 
Value stream mapista havaitaan, että koodin valmistumisesta (code and test) menee 1.5 viikkoa sen tuotantoon saamiseen (deploy).

- Miksi? QA-osaston on vielä varmistettava, että koodi toimii staging-ympäristössä.
- Miksi? Ohjelmoijilla ei ole aikaa testata koodia itse staging-ympäristössä.
- Miksi? Ohjelmoijilla on kiire sprintin tavoitteena olevien user storyjen - tekemisessä.
- Miksi? Edellisten sprinttien aikana tehtyjen storyjen bugikorjaukset vievät - yllättävän paljon aikaa.
- Miksi? Laadunhallintaa ei ehditä koskaan tekemään kunnolla siinä sprintissä missä - storyt toteutetaan.
- Miksi? Sprintteihin otetaan aina liian monta user storya.

Esimerkin opetus:
- ongelma (pitkä deploy-viive) ei ollut QA:ssa tai kehittäjissä
- perimmäinen syy oli **liian suuri työmäärä sprintissä**

-> Todellinen parannus syntyy vasta, kun korjataan **juurisyy**, ei vain näkyvää ongelmaa.

---

## Kappaleen tiivistys
Kaizen on Lean-ajattelun ydin: kaikkien työntekijöiden jatkuva pyrkimys parantaa omaa työtään. Se toteutuu pieninä, toistuvina parannuksina, joita tuetaan kaizen eventeillä, kuten retrospektiiveillä. Hukkaa etsitään työkaluilla kuten value stream mapping, ja ongelmien perimmäiset syyt selvitetään five whys -menetelmällä. Tavoitteena ei ole hetkellinen optimointi, vaan pysyvä, oppiva ja kehittyvä toimintakulttuuri.

---

## Leanin periaate: Pull-systeemi (tiivistelmä)

### Tavoite
Leanin tavoitteena on **lyhentää aikaa ideasta asiakkaalle**.  
Tämä saavutetaan optimoimalla **arvon virtaus (flow)** ja poistamalla turhat viiveet ja työvaiheet.

---

## Pull vs. Push

### Pull-systeemi (imuohjaus)
- Työ tehdään **vain todelliseen tarpeeseen**
- Tuote tai komponentti valmistetaan **vasta tilauksen jälkeen**
- Tukee **Just In Time (JIT)** -tuotantoa

**Esimerkki:** pizzeria – pizza tehdään vasta tilauksen jälkeen

### Push-systeemi
- Työtä tehdään **etukäteen varastoon**
- Toivotaan, että tuotokset menevät myöhemmin kaupaksi

**Esimerkki:** lounasravintola – ruoka tehdään etukäteen

-> Lean suosii **pull-systeemiä**, koska se vähentää varastoja, virheitä ja pääoman sitoutumista.

---

## Kanban – pull-systeemin työkalu

**Kanban** on visuaalinen ohjausjärjestelmä, joka:
- käyttää näkyviä kortteja (”card you can see”)
- ohjaa työn etenemistä vaiheesta toiseen
- rajoittaa samanaikaisen työn määrää

Keskeiset periaatteet:
- Kanban-kortteja on **rajallinen määrä**
- Työtä **vedetään eteenpäin** tarpeen mukaan
- Estää työn kasaantumisen yksittäisiin vaiheisiin

-> Kanban auttaa pitämään **välivarastot (WIP)** hallinnassa, jotka ovat leanin mukaan hukkaa.

---

## Kanban ohjelmistokehityksessä

Ohjelmistotuotannossa:
- Kanban-kortti = user story tai task
- Kortti kulkee työvaiheiden (esim. analyysi → kehitys → testaus) läpi

### WIP-rajoitteet (Work In Progress)
- Rajoittavat keskeneräisen työn määrää
- Parantavat virtausta ja lyhentävät läpimenoaikaa
- Liian suuret WIP-rajat → hidas virtaus ja paljon hukkaa

-> Leanin näkökulmasta keskeneräinen työ on **hukka**.

---

## One piece flow ja käytännön kompromissit
Lean-ihanne:
- **One piece flow** – yksi työ valmiiksi ennen seuraavaa

Todellisuus:
- Liian tiukka malli voi aiheuttaa:
  - odottelua
  - alhaista käyttöastetta

Siksi:
- useimmiten työstetään **useampaa storya rinnakkain**
- sopivat WIP-rajoitteet löytyvät **tiimikohtaisesti kokeilemalla**

---

## Kappaleen tiivistys
Pull-systeemi on leanin keskeinen periaate, jossa työ tehdään vain todelliseen tarpeeseen arvon virtauksen optimoimiseksi. Kanban toteuttaa pull-ajattelua rajoittamalla keskeneräistä työtä ja tekemällä työn etenemisen näkyväksi. Ohjelmistokehityksessä kanban-taulut ja WIP-rajoitteet auttavat lyhentämään läpimenoaikaa, mutta optimaalinen taso vaatii tiimikohtaista harkintaa ja jatkuvaa parantamista.

---

## Arvon virtaaminen ketterässä ohjelmistotuotannossa

Ketterässä ohjelmistotuotannossa lean-periaatteet näkyvät erityisesti **arvon virtauksen optimointina**.  
Vaatimuksia hallitaan **product backlogilla**, joka on parhaimmillaan **DEEP**:
- **Detailed appropriately** – vain tarpeellinen tarkkuus
- **Emergent** – vaatimukset tarkentuvat ajan myötä
- **Estimated** – työmäärä arvioitu
- **Prioritized** – tärkeimmät ensin

### Vaatimusten määrittely ja toteutus
- Alhaisen prioriteetin user storyja ei määritellä tarkasti etukäteen.
- Storyt tarkennetaan vasta **viimeisellä vastuullisella hetkellä** (*last responsible moment*).
- Sprinttiin valitut tehtävät toteutetaan **valmiiksi asti sprintin aikana** (*deliver as fast as possible*).

### Scrum leanin näkökulmasta
- Scrum toimii **pull-systeeminä**:
  - Product owner valitsee sprinttiin tärkeimmät tarpeet
  - Tiimi toteuttaa ne mahdollisimman nopeasti
- Arvo virtaa asiakkaalle **sprinttien rytmissä** valmiina toiminnallisuuksina.
- Kesken olevan työn määrää rajoitetaan sprintin laajuudella, mikä vähentää leanin mukaista hukkaa.

### Kehitys kohti jatkuvaa virtausta
- Perinteinen malli: julkaisut sprinteittäin (viikkojen välein).
- Uudempi trendi: **continuous deployment**
  - jopa jokainen commit voi johtaa julkaisuun
  - arvoa voidaan toimittaa useita kertoja päivässä

### Sprintit vs. jatkuva pull
- Aikarajoitettu sprintti ei sovi kaikkiin konteksteihin.
- Joissain tapauksissa siirrytään **puhtaampaan pull-malliin**:
  - työstetään yksi (tai muutama) story kerrallaan
  - uusi työ aloitetaan vasta, kun edellinen on valmis
- **Scrumban** yhdistää Scrumin ja Kanbanin ja tukee tätä lähestymistapaa.

### Ydinajatus
Arvon tehokas virtaaminen syntyy, kun:
- vaatimukset määritellään juuri ajoissa
- kesken olevaa työtä rajoitetaan
- toiminnallisuudet viedään nopeasti tuotantoon

---

## Kasvattaminen leaniin ja johtajuuden periaatteet

Lean-ajattelu Toyotalla perustuu **systemaattiseen oppimiseen ja johtajuuden kehittämiseen**.

### Lean-ajatteluun kasvattaminen
- Uudet työntekijät koulutetaan **käytännön työn kautta** useiden kuukausien ajan.
- Työntekijät kiertävät eri tehtävissä ja oppivat tunnistamaan **lean-hukan** eri muodot.
- Tavoitteena on sisäistää **kaizen-mentaliteetti**: jatkuva parantaminen osana päivittäistä työtä.

### Johtajuus Toyotalla
- Johtajat toimivat ensisijaisesti:
  - **opettajina**
  - **mentoreina**
  - **valmentajina**
- Periaate **grow leaders**: organisaatio kasvattaa sisältä käsin johtajia, jotka ymmärtävät leanin syvällisesti.

### Johtaja ymmärtää työn
- Periaate *“my manager can do my job better than me”*:
  - Johtajat ovat edenneet tehtäviinsä käytännön työn kautta
  - He ymmärtävät ja osaavat myös työntekijöiden **hands-on-työn**
- Johtajan rooli ei ole vain hallinnollinen, vaan **aktiivinen tuki arjessa**.

### Go see – johda etulinjasta
- Periaate **go see (genchi genbutsu)**:
  - Ongelmat ymmärretään parhaiten siellä, missä työ tehdään
- Johtajien tulee toimia **gembassa** (työn todellisessa ympäristössä), ei pelkästään raporttien pohjalta.
- Todelliset faktat löytyvät työpaikalta, ei työpöydän äärestä.

### Yhteys ketterään kehitykseen
- **Scrum masterin rooli** heijastaa osin lean-johtajuutta (esteiden poistaminen, tiimin tukeminen).
- Teknistä johtajuutta edustavat usein:
  - lead developerit
  - senior developerit
- Kokeneemmat kehittäjät toimivat käytännössä **mentoreina ja valmentajina**.

### Ydinajatus
Lean-johtajuus tarkoittaa:
- oppimista työn kautta
- johtamista esimerkillä
- jatkuvaa parantamista
- ja vahvaa läsnäoloa siellä, missä arvo syntyy

---
## Lean-tuotekehityksen periaatteet – tiivistelmä

### Lean tuotannossa vs. tuotekehityksessä
- **Tuotannossa (production)** lean keskittyy ensisijaisesti **hukan eliminointiin** ja prosessin tehostamiseen.
- **Tuotekehityksessä (development)** painopiste siirtyy **oppimisen nopeuttamiseen** ja parempien päätösten tekemiseen epävarmuuden keskellä.

### Oppimisen kiihdyttäminen
- Lean-tuotekehityksen ydinajatus:  
  **“Out-learn the competitors”** – opi kilpailijoita nopeammin.
- Tavoitteena on tuottaa **arvokasta tietoa (high-value information)**.
- Huomio kohdistetaan erityisesti:
  - epävarmoihin asioihin  
  - korkean teknisen riskin ideoihin  
- Näitä testataan nopeasti, koska **viivästynyt tieto on kallista** (cost of delay).

### Set-based concurrent development
- Kehitetään **useita vaihtoehtoisia ratkaisuja rinnakkain**.
- Vaihtoehtoja verrataan säännöllisesti ja heikoimmat karsitaan.
- Lopulta valitaan paras ratkaisu.
- Eroaa perinteisestä iteratiivisesta kehityksestä, jossa parannetaan yhtä ratkaisua kerrallaan.
- Ohjelmistokehityksessä käytössä harvoin, lähinnä esim. käyttöliittymäsuunnittelussa.

### Johtajuus tuotekehityksessä
- Toyotalla tuotekehitystä johtaa **chief technical engineer**:
  - vastaa sekä teknisestä että liiketoiminnallisesta menestyksestä
  - toimii etulinjassa
  - tuntee käytännön työn ja asiakkaan tarpeet
- Rooli eroaa Scrumin product ownerista vahvan teknisen taustan vuoksi.

---

## Lean-tuotekehityksen periaatteet – tiivistelmä

### Lean tuotannossa vs. tuotekehityksessä
- **Tuotannossa (production)** lean keskittyy ensisijaisesti **hukan eliminointiin** ja prosessin tehostamiseen.
- **Tuotekehityksessä (development)** painopiste siirtyy **oppimisen nopeuttamiseen** ja parempien päätösten tekemiseen epävarmuuden keskellä.

### Oppimisen kiihdyttäminen
- Lean-tuotekehityksen ydinajatus:  
  **“Out-learn the competitors”** – opi kilpailijoita nopeammin.
- Tavoitteena on tuottaa **arvokasta tietoa (high-value information)**.
- Huomio kohdistetaan erityisesti:
  - epävarmoihin asioihin  
  - korkean teknisen riskin ideoihin  
- Näitä testataan nopeasti, koska **viivästynyt tieto on kallista** (cost of delay).

### Set-based concurrent development
- Kehitetään **useita vaihtoehtoisia ratkaisuja rinnakkain**.
- Vaihtoehtoja verrataan säännöllisesti ja heikoimmat karsitaan.
- Lopulta valitaan paras ratkaisu.
- Eroaa perinteisestä iteratiivisesta kehityksestä, jossa parannetaan yhtä ratkaisua kerrallaan.
- Ohjelmistokehityksessä käytössä harvoin, lähinnä esim. käyttöliittymäsuunnittelussa.

### Johtajuus tuotekehityksessä
- Toyotalla tuotekehitystä johtaa **chief technical engineer**:
  - vastaa sekä teknisestä että liiketoiminnallisesta menestyksestä
  - toimii etulinjassa
  - tuntee käytännön työn ja asiakkaan tarpeet
- Rooli eroaa Scrumin product ownerista vahvan teknisen taustan vuoksi.

---

## Lean ja ketterät menetelmät

### Lean ja Scrum
- Lean on vaikuttanut vahvasti ketteriin menetelmiin, erityisesti Scrumiin.
- Vaikka terminologia eroaa, perusajatus on sama:
  - **jatkuva parantaminen**
  - **inspect & adapt**
- Kaizen ja ketterä retrospektiivisykli edustavat samaa periaatetta.

### Moderni ohjelmistokehitys
- Painopiste on siirtynyt yhä enemmän:
  - arvon läpimenoajan minimointiin
  - jatkuvaan toimittamiseen
- Nykyään puhutaan yhä useammin **leanista ohjelmistokehityksestä**.

### Lean ei ole työkalupakki
- Lean ei ole kokoelma menetelmiä, vaan **ajattelutapa ja kulttuuri**.
- Toyotan perusajatus:
  - tyytymättömyys nykytilaan
  - jatkuva kysymys: *“Miksi teemme tämän näin?”*
- Parannuskokeiluja tehdään **loputtomana syklinä**, ei kertaluonteisesti.

### Haasteet soveltamisessa
- Lean on kehittynyt Toyotan tarpeisiin vuosikymmenten aikana.
- Käytänteiden siirtäminen muihin konteksteihin ei ole suoraviivaista.
- Sekä lean että ketterät menetelmät vaativat:
  - kulttuurin muutosta
  - pitkäjänteisyyttä
  - jatkuvaa oppimista


## Laajan skaalan ketterä ohjelmistokehitys – tiivistelmä

### Miksi ketteryyttä pitää skaalata?
- Ketterät menetelmät (esim. Scrum) on alun perin tarkoitettu **pienille tiimeille** (3–9 henkeä).
- Suurissa tuotteissa tarvitaan **useita tiimejä**, joita täytyy **koordinoida**.
- Perusidea: pidä tiimit pieninä, lisää kapasiteettia tiimien määrällä.

---

## Scrum of Scrums

### Scrum of Scrums (SoS)
- **Kevyt koordinointimalli** useille Scrum-tiimeille.
- Koostuu edustajista jokaisesta tiimistä:
  - usein **Scrum Mastereista**
  - joskus **Lead Developereista**
- Tapaamiset:
  - päivittäin tai viikoittain tarpeen mukaan
- Käytössä jo 1990-luvulta (Jeff Sutherland).

### Management Scrum / Scrum of Scrum of Scrums
- Ylempi koordinointitaso suurissa organisaatioissa.
- Osallistujia:
  - johto
  - tuotepäälliköt
  - pääarkkitehdit
- Käsittelee useita tuotteita ja strategista ohjausta.
- Ei määrittele tarkasti backlogien hallintaa.

---

# Laajan skaalan ketterät menetelmät

### Yleistä
- Viimeisen ~10 vuoden aikana kehitetty erityisiä **skaalausmalleja**.
- Tunnetuimmat:
  - **SAFe** (Scaled Agile Framework)
  - **LeSS** (Large Scale Scrum)
  - **Disciplined Agile (DA)**
  - **Scrum@Scale**
- Yhteistä:
  - yhdistävät **ketteryyttä ja lean-ajattelua**
  - huomioivat koko organisaation, eivät vain tiimejä

---

## SAFe – Scaled Agile Framework

### Perusidea
- **Suosituin** laajan skaalan ketterä malli.
- Kehittäjä: **David Leffingwell**
- Taustalla Nokian kehitystyö.
- Ensimmäinen versio 2011, nykyisin versio 6.0.

### Mitä SAFe tarjoaa?
- Laaja **kehys (framework)**:
  - periaatteita (principles)
  - rooleja
  - käytänteitä
  - käsitteitä
- Yritykset **räätälöivät** oman prosessinsa SAFen pohjalta.

### SAFe-konfiguraatiot
- **Essential SAFe** – pienemmät organisaatiot
- **Large Solution SAFe**
- **Portfolio SAFe**
- **Full SAFe** – suurimmat organisaatiot ja tuoteportfoliot

### Keskeisiä käsitteitä
- **Release Train (ART)**  
  - usean Scrum-tiimin synkronoitu kokonaisuus
- **Product Increment (PI)**  
  - usean sprintin mittainen kehitysjaks o
- **Top-down-ohjaus**  
  - koordinointi ja päätöksenteko tapahtuu hierarkkisesti

### Vahvuudet
- Selkeä, hyvin dokumentoitu
- Tarjoaa rooleja ja rakenteita johdolle

### Kritiikki
- Raskas prosessi
- Kritiikki top-down-luonteesta
- Kyseenalaistettu ketteryys (Ken Schwaber)

---

## LeSS – Large Scale Scrum

### Perusidea
- Kehittäjät: **Craig Larman & Bas Vodde**
- **Erittäin kevyt**, suoraan Scrumiin pohjautuva
- Ei uusia rooleja, artefakteja tai seremonioita

### LeSS-versiot
- **LeSS**: 2–8 Scrum-tiimiä
- **LeSS Huge**: enemmän tiimejä

### LeSS:n perusoletukset
- Yksi tuote
- Yksi **Product Owner**
- Yksi **Product Backlog**
- Synkronoidut sprintit
- **Cross-functional tiimit**
- Yksi **shippable product increment** per sprintti

### Rajaus
- Yksi LeSS-toteutus = yksi tuote
- Ei ota kantaa tuoteportfolion hallintaan (toisin kuin SAFe)

---

## LeSS:n taustaperiaatteet

### More with Less
- Vähemmän:
  - rooleja
  - artefakteja
  - prosesseja
- Enemmän:
  - tiimien vastuuta
  - omistajuutta
  - asiakaslähtöisyyttä
  - oppimista

### Keskeinen ajatus
- Yksinkertaisuus pakottaa tiimit ottamaan vastuun:
  - tuotteesta
  - prosessista
  - asiakasyhteistyöstä

---

## SAFe vs. LeSS (lyhyesti)

| SAFe | LeSS |
|-----|------|
| Raskas, kattava kehys | Kevyt ja minimalistinen |
| Top-down-ohjaus | Tiimien omistajuus |
| Paljon rooleja | Ei uusia rooleja |
| Sopii suurille organisaatioille | Sopii yhden tuotteen kehitykseen |
| Johdon suosima | Kehittäjälähtöinen |

---

## Yhteenveto
- Ketteryyden skaalaus vaatii **koordinaatiota**, ei suuria tiimejä.
- **SAFe** tarjoaa rakenteen ja hallinnan suurille organisaatioille.
- **LeSS** säilyttää Scrumin ytimen ja luottaa tiimien vastuullisuuteen.
- Valinta riippuu:
  - organisaation koosta
  - kulttuurista
  - johdon ja tiimien kypsyydestä


## LeSS käytännössä (2–8 tiimiä) – tiivistelmä

### Konfiguraatio
- **LeSS (pieni konfiguraatio)** on tarkoitettu noin **2–8 Scrum-tiimin** koordinointiin.
- Perustuu **suoraan Scrumiin**, ei lisää uusia raskaita rakenteita.

---

## Roolit

### Product Owner
- **Yksi Product Owner** koko tuotteelle.
- Vastaa **priorisoinnista ja backlogista**.

### Scrum Master
- Scrum mastereita voi olla useita.
- Yksi Scrum Master tukee tyypillisesti **1–3 tiimiä**.

### Tiimit
- **Itseorganisoituvia feature-tiimejä**.
- Tiimit eivät ole jaettu arkkitehtuurikerroksittain:
  - ei erillisiä frontend-, backend- tai tietokantatiimejä
- Jokainen tiimi toteuttaa:
  - user storyn **alusta loppuun**
  - kaikkien kerrosten yli
  - **Definition of Done** -tasolle

---

## Artefaktit

### Product Backlog
- **Yksi yhteinen product backlog** koko tuotteelle.

### Sprint Backlog
- **Tiimikohtainen sprint backlog** jokaisella tiimillä.
- Tarvittaessa:
  - useampi tiimi voi käyttää **yhteistä sprint backlogia**

### Product Increment
- Sprintin tuloksena syntyy:
  - **one shippable product increment**
- Kaikki tiimit työstävät **samaa ohjelmistoa**
- Increment on:
  - potentiaalisesti julkaistavissa
  - yhteinen kaikille tiimeille

---

## Sprint Planning LeSS:issä

### Osa 1: Yhteinen suunnittelu
- Product Owner + kaikkien tiimien edustajat
- Valitaan:
  - mitä user storyja kukin tiimi toteuttaa seuraavassa sprintissä

### Osa 2: Tiimikohtainen suunnittelu
- Kukin tiimi:
  - muodostaa oman sprint backloginsa
  - suunnittelee työnsä normaalin Scrumin tapaan

---

## Review ja retrospektiivit

### Sprint Review
- Kaikkien tiimien **yhteinen katselmointi**
- Tarkastellaan:
  - koko tuotteen incrementtiä

### Retrospektiivit
- **Kaksitasoinen malli**:
  1. Tiimikohtainen retrospektiivi
  2. **Overall-retrospektiivi**
     - mukana edustus kaikista tiimeistä
     - tarvittaessa myös yrityksen johto
     - keskittyy koko tuotantoprosessiin

---

## Tiimien välinen koordinointi

### Perusperiaate
- LeSS ei pakota erillisiä koordinaatiopalavereita.
- Tiimit **päättävät itse**, miten koordinoivat työnsä.

### Suositukset
- **Decentralized coordination**  
  → vältä keskitettyä ohjausta
- **Just talk**  
  → suora keskustelu ensisijaista
- **Communicate in code**  
  → yhteiset koodikäytännöt, CI, yhteinen koodi
- **Scouts**  
  → tiimien edustajat vierailevat toisten tiimien dailyissa
- **Scrum of Scrums**
  - sallittu
  - ei ensisijainen ratkaisu

---

## Backlogin ylläpito (Refinement)

### Vastuut
- **Product Owner**
  - vastaa priorisoinnista
- **Tiimit**
  - osallistuvat backlog refinementiin

### Käytännöt
- Noin **5–10 %** sprintin ajasta backlog-työhön
- Oletus:
  - tiimi tarkentaa ne storyt, joita se todennäköisesti toteuttaa
- Tarvittaessa:
  - yhteisiä grooming-tilaisuuksia
  - erityisesti arkkitehtuuriin tai laajempiin kokonaisuuksiin liittyen

### Asiakasyhteys
- LeSS kannustaa:
  - **suoraan kommunikaatioon asiakkaiden ja loppukäyttäjien kanssa**
  - ei pelkästään Product Ownerin kautta

---

## Yhteenveto

- LeSS säilyttää Scrumin ytimen myös laajassa mittakaavassa.
- Yksi tuote, yksi backlog, yksi incrementti.
- Vähemmän prosessia → enemmän tiimien vastuuta.
- Koordinointi tapahtuu ensisijaisesti:
  - suoralla kommunikoinnilla
  - yhteisen koodin kautta
  - ei raskailla hallintorakenteilla.

## LeSS Huge – tiivistelmä

### Milloin LeSS Huge?
- Käytetään, kun:
  - **Scrum-tiimejä on yli 8**
- Lähtöoletukset säilyvät:
  - **Yksi tuote**
  - **Yksi product backlog**
  - **Yksi kokonaisuudesta vastaava Product Owner**

---

### Requirement Area (vaatimusalue)
- Product backlog jaetaan **vaatimusalueisiin** (*requirement area*).
- Kukin vaatimusalue:
  - kattaa loogisen osan tuotteesta
  - ei vastaa organisaatiorakennetta tai teknistä kerrosta

---

### Area Product Owner (APO)
- Jokaisella vaatimusalueella on oma:
  - **Area Product Owner**
- Vastaa:
  - oman alueensa backlog-työstä
  - yhteistyöstä tiimien kanssa

---

### Product Owner -tiimi
- Area Product Ownerit muodostavat:
  - **Product Owner -tiimin**
- Tiimi:
  - koordinoi koko tuotteen kehitystä
  - toimii **kokonais-Product Ownerin** johdolla
- Kokonais-Product Owner:
  - vastaa tuotteen kokonaisprioriteeteista
  - varmistaa, että alueet muodostavat yhtenäisen tuotteen

---

## LeSS vs SAFe – tiivis vertailu

### Yhteinen tausta
- Molemmat:
  - syntyneet **Suomessa**
  - saaneet alkunsa **Nokian** ympäristössä
- Taustaperiaatteet:
  - ketteryys
  - lean-ajattelu

---

### Keskeiset erot

| LeSS | SAFe |
|-----|------|
| Erittäin **kevyt** | **Raskas ja laajasti määritelty** |
| Perustuu suoraan Scrumiin | Yhdistää Scrum + XP + Lean + management-käytännöt |
| Vähän rooleja ja artefakteja | Paljon rooleja, käsitteitä ja prosesseja |
| Korostaa **tiimien omistajuutta** | Korostaa **top-down-ohjausta** |
| Yksi tuote kerrallaan | Soveltuu tuoteportfolioihin |
| Suosittu kehittäjien keskuudessa | Suosittu yritysjohdon keskuudessa |

---

### Kritiikki ja käytännön kokemukset
- **SAFe**:
  - saanut paljon kritiikkiä ketteryyden edustajilta
  - koetaan usein raskaaksi
  - harvoin kehittäjien suosiossa
- **LeSS**:
  - korostaa yksinkertaisuutta
  - säilyttää ketteryyden perusajatuksen
  - käytössä edelleen Nokialla (ent. NSN)

---

## Yhteenveto

- **LeSS Huge** mahdollistaa yhden tuotteen kehittämisen erittäin suuressa mittakaavassa ilman raskasta hallintorakennetta.
- **LeSS** pyrkii maksimoimaan:
  - tiimien vastuun
  - suoran asiakasyhteyden
  - oppimisen ja jatkuvan parantamisen
- **SAFe** tarjoaa:
  - selkeän mutta raskaan mallin
  - erityisesti yritysjohdon tarpeisiin
- Menetelmien ero ei ole tekninen vaan **filosofinen**:
  - LeSS: *more with less*
  - SAFe: *structure and control*
---

## Spotifyn ketterän skaalaamisen viitekehys – tiivistelmä

### Tausta
- Henrik Kniberg kuvasi vuonna 2012, miten **Spotify skaalasi ketterän kehityksensä**:
  - muutamasta kehittäjästä → satoihin
  - useisiin kaupunkeihin
  - säilyttäen **startup-maisen ketteryyden**
- Tarkoitus ei ollut luoda kopioitavaa mallia, mutta sellaisena se usein tulkittiin.

---

## Keskeiset rakenteet

### Squad (tiimi)
- **5–10 hengen cross-functional tiimi**
- Vastaa yhdestä **asiakkaalle arvoa tuottavasta kokonaisuudesta**
- Täysin **itseorganisoituva**
- Valitsee itse työskentelytapansa:
  - Scrum, Kanban, Scrumban, tms.
- Tiimi:
  - vie idean tuotantoon asti
  - toimii **feature-tiiminä**
- Roolit:
  - **Product Owner**: ohjaa *mitä rakennetaan*
  - **Agile coach**: tukee ketteryyttä (Scrum Master -henkinen rooli)
- Tiimit:
  - ovat suorassa yhteydessä käyttäjiin
  - hyödyntävät **Lean Startup** -ajattelua:
    - MVP:t
    - A/B-testaus
- Tiimeillä on laaja **autonomia**, myös liiketoimintapäätöksissä.

#### Tiimien toimivuutta mitataan mm.
- tuen riittävyys (PO, coach)
- vaikutusmahdollisuudet omaan työhön
- julkaisun helppous (*easy to release*)
- prosessin sopivuus tiimille
- mission selkeys
- muun organisaation tuki

---

### Tribe (heimo)
- **Useista samaan aihepiiriin liittyvistä tiimeistä koostuva kokonaisuus**
- Maksimikoko:
  - ~100 henkilöä (**Dunbarin luku**)
- Tiimit:
  - työskentelevät fyysisesti lähekkäin
- Tavoite:
  - helppo epämuodollinen kommunikointi
  - vähän byrokratiaa
- Heimot pitävät yhteisiä demoja ja tilaisuuksia.

---

### Chapter (jaosto)
- **Saman heimon sisäinen osaamisyhteisö**
- Perustuu **kompetenssiin** (esim. frontend, testaus)
- Tarkoitus:
  - jakaa oppeja tiimien välillä
  - estää osaamisen siiloutuminen
- **Chapter lead**:
  - seniori
  - toimii itse myös tiimissä
- Vastaa kysymykseen:
  - *“How to build it well?”*
- Tukee:
  - ammatillista kehittymistä
  - yhteisiä käytänteitä

---

### Guild (kilta)
- **Yli heimorajojen toimiva yhteisö**
- Perustuu:
  - yhteiseen kiinnostukseen tai osaamiseen
- Avoin:
  - myös muille kuin varsinaisille asiantuntijoille
- Tarkoitus:
  - laajempi tiedon jakaminen
  - yhteisöllisyys

---

## Spotifyn mallin luonne ja kritiikki

### Ei varsinainen menetelmä
- Knibergin mukaan:
  - **“Spotify-mallia ei ole olemassa”**
- Toimintatavat:
  - muuttuvat jatkuvasti
  - mukautuvat organisaation kasvuun

### Kritiikki
- Mallin kopioiminen sellaisenaan on ongelmallista:
  - konteksti ratkaisee
- Monet käsitteet ovat:
  - uudelleennimettyjä tuttuja asioita Scrumin, Leanin, SAFe:n ja LeSS:n piiristä
- Suosioon vaikuttanut:
  - **halo effect** (Spotifyn brändin sädekehä)
- Nopean kasvun myötä:
  - Spotify on lisännyt rakenteita (esim. trio, allianssi)
  - liikkunut osin kohti perinteisempää organisaatiota

---

## Yhteenveto

- Spotifyn viitekehys korostaa:
  - pieniä, autonomisia tiimejä
  - nopeaa päätöksentekoa
  - asiakasläheisyyttä
  - oppimista ja kokeilua
- Se **ei ole valmis resepti**, vaan:
  - kuvaus yhdestä ajankohdasta
  - inspiraation lähde
- Mallia ei tule kopioida sellaisenaan, vaan:
  - ymmärtää periaatteet
  - soveltaa omaan kontekstiin

---
# Ketterien menetelmien käyttö ja hyödyt – tutkimusten tiivistelmä

### Ketterien menetelmien käyttöaste

- Ketterät menetelmät ovat nykyään **valtavirtaa**, minkä vuoksi tuoreita käyttöastetutkimuksia on vähän.
- Vuoden 2018 katsauksen (Max Steinmetz) mukaan:
  - **46 %** ohjelmistoprojekteista ketteriä (PMI)
  - **85,9 %** vastaajista työskenteli ketterästi (Stack Overflow, >100 000 vastaajaa)
  - Useimmat kyselyt sijoittuvat **selvästi yli 50 %**:n

!!! Monet internet-kyselyt eivät ole tieteellisesti edustavia (otos, metodologia, kaupalliset intressit).

---

### Tieteellisiä ja puolivirallisia tutkimuksia

- **Suomi 2012 (Oulun yliopisto, 200 yritystä)**  
  - **58 %** käytti ketteriä tai lean-menetelmiä

- **Brasilia, Suomi, Uusi-Seelanti 2016**  
  Käytetyt menetelmät:
  - Scrum **71,2 %**
  - Kanban **49,5 %**
  - Lean **39,7 %**
  - Vesiputous **35,3 %**

- **HY & Nitor 2018**  
  - Vain **5,9 %** ilmoitti, ettei ketteriä menetelmiä käytetä lainkaan

-> Ketterien menetelmien käyttö on erittäin laajaa myös julkisella sektorilla (esim. USA:n hallinto).

---

## State of Agile -raportit

### Menetelmät (2022)
- **Scrum dominoi** ketteriä menetelmiä selvästi

### Projektinhallintakäytänteet (2021)
- **63 %** käyttää *short iterations*
- Vain noin **50 %** tiimeistä käyttää product owneria tai vastaavaa
- Huomio:
  - **37 %** ei käytä lyhyitä iteraatioita
  - Tämä viittaa usein ns. *ScrumBut*-ilmiöön

### Tekniset käytänteet (2020)
- Jatkuva integraatio käytössä vain **55 %**:lla
- Monet keskeiset tekniset käytänteet ovat yllättävän harvinaisia

!!! **49 %** ei julkaise ohjelmistosta uusia versioita usein (*frequent releases*), vaikka:
- pienet toimituserät
- WIP-rajoitukset  
on todettu tehokkuutta parantaviksi

---

## Toimiiko ketterä kehitys? (Standish Group – Chaos Report 2020)

### Projektien onnistumiskategoriat
- **Successful**: aikataulu, budjetti ja laajuus toteutuvat
- **Challenged**: jokin osa-alue pettää
- **Failed**: projekti keskeytyy tai ei oteta käyttöön

### Tulokset
- Ketterät menetelmät **toimivat paremmin kuin vesiputous** kaikissa projektikokoluokissa
- Ero **kasvaa projektin koon kasvaessa**
- Suuret projektit ovat riskialttiita menetelmästä riippumatta

-> Suositus: **pilko suuret hankkeet pienemmiksi**

!!! Chaos Reportin heikkous:
- kaupallinen
- raakadata ei julkista

---

## Ketteryyden hyödyt (State of Agile)

- Parempi kyky vastata muutoksiin
- Nopeampi toimitustahti
- Parempi näkyvyys ja yhteistyö
- Parantunut laatu ja asiakastyytyväisyys

---

## Tutkimusten rajoitteet ja kriittiset huomiot

- Suurin osa tutkimuksista on:
  - kyselypohjaisia
  - käsitteistöltään epätarkkoja
  - mahdollisesti puolueellisia
- Akateemisen tutkimuksen laatu ja yleistettävyys vaihtelee

### Yksittäisten tekniikoiden tutkimus
- Esim. TDD, pariohjelmointi, CI
- Vaikea eristää yhden tekniikan vaikutusta
- Tulokset eivät välttämättä yleisty

### Pitkän aikavälin näkökulma
- **79 % ohjelmiston kustannuksista syntyy ylläpitovaiheessa**
- Lyhyen aikavälin hyödyt voivat peittää:
  - pitkän aikavälin kustannuksia
  - heikentynyttä ylläpidettävyyttä

---

## Yhteenveto

- Ketterät menetelmät ovat laajasti käytössä ja **toimivat keskimäärin paremmin** kuin perinteiset mallit
- Hyötyjen realisoituminen edellyttää:
  - myös teknisten käytänteiden käyttöönottoa
  - ei pelkkää seremonioiden noudattamista
- Tutkimusnäyttö tukee ketteryyttä, mutta:
  - ei ole täysin kiistatonta
  - konteksti ja ihmiset ratkaisevat
