# Tiivistelmä: Ohjelmistotuotanto ja sen osa-alueet

## 1. Mitä ohjelmistotuotanto tarkoittaa?
IEEE määrittelee ohjelmistotuotannon (software engineering) näin:

> “Systemaattinen, kurinalainen ja mitattavissa oleva tapa kehittää, operoida ja ylläpitää ohjelmistoja; toisin sanoen insinöörimäinen lähestymistapa ohjelmistojen tekemiseen.”

Määritelmä korostaa:
- **systemaattisuutta**
- **kurinalaisuutta**
- **mitattavuutta**
- **insinöörimäistä otetta**

Taustalla oleva standardi on **SWEBOK** (Software Engineering Body of Knowledge), joka määrittelee ohjelmistotuotannon sisällön ja osa-alueet.

### Terminologiahuomio
- Englanniksi: *software engineering*
- Suomeksi: *ohjelmistotuotanto* – hieman harhaanjohtava, koska ei vastaa sanaa *engineering* vaan kuulostaa enemmän *production*-termiltä
- Oikeampi ajatus: ohjelmistokehitys on **kehittämistä (development)**, joka sisältää suunnittelun, tarpeiden määrittelyn ja toteutuksen – ei vain suoraviivaista “valmistamista”.

---

## 2. Ohjelmistotuotannon osa-alueet (SWEBOK)
Alla SWEBOKin määrittelemät 14 osa-aluetta, selityksineen:

### 1. **Software requirements**
Ohjelmiston **vaatimukset**: mitä ohjelmiston tulee tehdä ja miksi. Vaatimukset tulevat käyttäjiltä tai tilaajilta.

### 2. **Software architecture**
Ohjelmiston **korkean tason rakenne**: millaisia pääkomponentteja on ja miten ne liittyvät toisiinsa. On suunnittelun tärkeä osa.

### 3. **Software design**
Ohjelmiston tarkemman **sisäisen rakenteen suunnittelu**: miten vaatimukset toteutetaan teknisesti.

### 4. **Software construction**
Ohjelmiston **rakentaminen**: ohjelmointi, debuggaus ja kaikki aktiviteetit, joilla suunnitelma muutetaan toimivaksi tuotteeksi.

### 5. **Software testing**
Menetelmät, joilla varmistetaan, että ohjelmisto toimii oikein ja on riittävän virheetön.

### 6. **Software maintenance**
Ohjelmiston **ylläpito** käyttöönoton jälkeen: bugikorjaukset, toiminnallisuuden laajennukset, parannukset. Useimmat ohjelmistot eivät koskaan “valmistu”.

### 7. **Software engineering operations**
Kaikki toimet, joilla varmistetaan, että ohjelmiston uudet versiot saadaan käyttäjille (julkaisu, toimitukset, käyttöönottoprosessit).

### 8. **Software configuration management**
Versiohallinta ja konfigurointi:
- kirjastot
- laitteistot
- käännösprosessin asetukset
- versioiden hallinta

### 9. **Software engineering management**
Ohjelmistokehityksen **suunnittelu, koordinointi, hallinta ja raportointi**. Käytännössä projektinhallinta ja tiimin johtaminen.

### 10. **Software engineering process**
Ohjelmistotuotantoprosessi: menetelmät, joilla kehittäjät organisoivat työnsä (requirements → design → construction → testing). Esim. ketterät menetelmät.

### 11. **Software engineering models and methods**
Yksityiskohtaiset menetelmät ja työkalut, kuten:
- mallinnus
- diagrammit
- suunnittelumetodologiat

### 12. **Software engineering economics**
Ohjelmistokehityksen **taloudelliset näkökulmat**: kustannukset, resurssit, investoinnit ja ohjelmistojen liiketoiminnallinen vaikutus.

### 13. **Software security**
Ohjelmiston **tietoturva**: suojautuminen haavoittuvuuksilta, hyökkäyksiltä ja väärinkäytöksiltä.

### 14. **Software quality**
Ohjelmiston **laatu** laajassa mielessä:
- ei vain bugittomuus
- tärkeämpää: täyttääkö ohjelmisto **käyttäjän tarpeen** ja onko se tarkoitukseensa sopiva

Laadun olennainen osa on tietoturva (*software security*).

---

## 3. Yhteenveto: miksi nämä ovat tärkeitä?
Ohjelmistotuotanto kattaa **laajan joukon osa-alueita**, jotka vaihtelevat:
- vaatimusten määrittelystä
- arkkitehtuuriin ja suunnitteluun
- toteutukseen, testaukseen ja ylläpitoon
- tietoturvaan, laatuun ja talouteen

Kurssin tavoitteena on antaa **kokonaiskuva** tästä kentästä. Syvällinen osaaminen syntyy myöhemmin käytännön kokemuksen ja syventävien kurssien kautta.

Aloittelijalle tärkeintä on:
1. ymmärtää ohjelmistotuotannon laaja kokonaisuus  
2. soveltaa opittua käytännön projekteissa (esim. Ohjelmistoprojekti tai työelämä)


# Tiivistelmä: Ohjelmiston vaiheet, elinkaari ja vesiputousmallin historia

## 1. Ohjelmiston vaiheet (software lifecycle)
Ohjelmistotuotannon keskeiset osa-alueet muodostavat ohjelmiston **vaiheet** eli elinkaaren:

- **Software requirements** – vaatimusten määrittely  
- **Software design** – suunnittelu  
- **Software construction** – toteutus / ohjelmointi  
- **Software testing** – testaus  
- **Software maintenance** – ylläpito  

Nämä vaiheet kuvaavat ohjelmiston etenemistä ideasta valmiiksi tuotteeksi ja edelleen käytössä olevaksi järjestelmäksi.

---

## 2. Code’n’fix – alkuajan ohjelmistokehitys
Varhaisina tietokoneaikoina ohjelmistot olivat yksinkertaisia ja halpoja verrattuna laitteisiin.  
Kehitystyö tehtiin **code’n’fix**-periaatteella:

1. koodaa  
2. kokeile toimiiko  
3. korjaa ja jatka  

Kun ohjelmistojen koko, monimutkaisuus ja käyttäjäkunta kasvoivat:
- projektit alkoivat myöhästyä  
- budjetit ylittyivät  
- laatu oli huono  
- ylläpito oli vaikeaa  
- joskus ohjelmistoa ei saatu toimitettua lainkaan  

---

## 3. Ohjelmistokriisi (software crisis)
Vuonna 1968 NATO:n konferenssissa todettiin, että maailmassa vallitsee **software crisis**.

Kriisi tarkoitti, että oli **vaikeaa tuottaa tehokkaita, laajennettavia ja oikein toimivia ohjelmistoja** saatavilla olevilla resursseilla.

Edsger Dijkstra kuvasi ongelmaa näin:
- Heikkojen koneiden aikaan ohjelmointi oli helppoa.  
- Tehokkaiden koneiden aikaan ongelmien koko kasvoi räjähdysmäisesti.

---

## 4. Ohjelmistokehitys insinööritieteenä (software engineering)
Ratkaisuksi kriisiin ehdotettiin **insinöörimäistä** lähestymistä ohjelmistokehitykseen.

Varhainen määritelmä (1968):

> “sound engineering principles in order to obtain economically software that is reliable and works efficiently”

Ajatus:
- ensin **määritellään** (requirements)  
- sitten **suunnitellaan** (design)  
- vasta lopuksi **toteutetaan** (construction)  

Tämä johti lineaaristen prosessimallien syntyyn.

---

## 5. Vesiputousmalli (waterfall model)
Winston Royce esitteli vuonna 1970 lineaarisen prosessimallin, jossa vaiheet suoritetaan **peräkkäin**:

`system requirements → software requirements → analysis → program design → coding → testing → operations`

Vesiputousmallin taustat:
- malli tuntui loogiselta: ensin selvitetään mitä tehdään, sitten suunnitellaan, sitten toteutetaan ja testataan
- USA:n puolustusministeriö (DoD) vaati mallin käyttöä (DoD STD 2167)
- yritykset omaksuivat mallin, koska “jos DoD vaatii sitä, sen täytyy olla hyvä”

Malliin liittyi vahva työnjako:
- analyytikot → vaatimukset  
- arkkitehdit → suunnittelu  
- ohjelmoijat → toteutus  
- testaajat → laadunvarmistus  

Työ vaiheitten välillä perustui raskaaseen dokumentointiin.  
Mallista käytettiin nimitystä **BDUF (Big Design Up Front)** – koko ohjelmisto suunnitellaan valmiiksi ennen yhtäkään koodiriviä.

---

## 6. Vesiputousmallin ongelmat
Käytännössä vesiputousmalli osoittautui huonoksi ohjelmistokehitykseen.

### Suurimmat ongelmat:
1. **Vaatimukset muuttuvat aina**  
   – asiakkaat eivät tiedä mitä haluavat  
   – toimintaympäristö muuttuu  
   – mitä pidempi projekti, sitä enemmän muutoksia  

2. **Asiakas ymmärtää tarpeensa vasta nähdessään ensimmäisen version**  
   → mutta vesiputousmallissa versio tulee vasta projektin lopussa

3. **Dokumentoidut vaatimukset ovat lähes aina epätarkkoja tai väärin tulkittuja**

4. **Suunnittelu ja toteutus eivät ole erotettavissa**  
   – valittu arkkitehtuuri vaikuttaa ominaisuuksien toteutusmahdollisuuksiin  
   – iso osa suunnittelua tapahtuu väistämättä ohjelmointivaiheessa

5. **Testaus tapahtuu liian myöhään**  
   – virheet löytyvät vasta lopussa  
   – korjaukset voivat vaatia suuria muutoksia arkkitehtuuriin tai jopa vaatimuksiin  
   – tämä tekee projektista kalliin ja riskialttiin

6. **Ohjelmointi ei ole mekaaninen “rakennusvaihe”**  
   → todellinen mekaaninen vaihe on vasta **kääntäminen**, ei ohjelmointi  
   → koodi on itse asiassa suunnitelma, ei pelkkä toteutus  

---

## 7. Roycen todellinen näkemys (suuri väärinymmärrys)
Paradoksaalista kyllä:
- Royce **ei suositellut** vesiputousmallin käyttöä.
- Hän esitteli sen vain **esimerkkinä mallista, joka EI toimi**.

Roycen varsinainen suositus:
- tee ensin **prototyyppi**
- paranna mallia opitun perusteella
- rakenna lopullinen versio **iteratiivisesti**

Royce siis ehdotti **kahden iteraation mallia**, ei lineaarista prosessia.

Vesiputousmallin suosio perustui siis **väärinymmärrykseen**.

---

## 8. Yhteenveto
- Ohjelmiston elinkaari koostuu vaiheista: requirements → design → construction → testing → maintenance.  
- Varhainen code’n’fix toimi pienissä projekteissa, mutta ei skaalautunut.  
- Tästä seurasi ohjelmistokriisi: laadun, aikataulujen ja kustannusten hallinta epäonnistui.  
- Ohjelmistotuotanto sai insinöörimäisen määritelmän: systemaattinen, kurinalainen prosessi.  
- Vesiputousmalli syntyi, mutta se perustui väärälle oletukselle ohjelmistojen ennustettavuudesta.  
- Vesiputousmalli ei toimi muuttuvissa, epäselvissä tai monimutkaisissa projekteissa.  
- Royce itse kannatti prototyyppien tekemistä ja iteratiivista kehitystä.  

Nykyiset ohjelmistoprosessit (esim. ketterät menetelmät) pohjautuvat pitkälti siihen, että vesiputousmallin ongelmat haluttiin ratkaista.

# Tiivistelmä: Iteratiivinen ja inkrementaalinen ohjelmistokehitys

## 1. Miksi iteratiivinen kehitys syntyi?
Iteratiivinen ohjelmistokehitys alkoi yleistyä 1990-luvulla vastauksena lineaarisen vesiputousmallin ongelmiin. Tunnettuja varhaisia iteratiivisia malleja ovat mm.:
- spiraalimalli  
- prototyyppimalli  
- Rational Unified Process (RUP)

Lineaarisen mallin ongelma oli, että vaatimuksia ei voi määritellä täydellisesti etukäteen ja muutokset tulevat väistämättä kesken projektin.

---

## 2. Iteratiivisen mallin perusidea
Iteratiivisessa mallissa kehitys jaetaan **iteraatioihin**, eli lyhyisiin aikajaksoihin.

Jokaisessa iteraatiossa tehdään kaikki vaiheita vastaavat työtehtävät:
- **määrittely**  
- **suunnittelu**  
- **toteutus**  
- **testaus**

### Lopputulos:
- ohjelmisto **kehittyy vähitellen** (eli on **inkrementaalinen**)  
- joka iteraatio tuottaa **valmiin, testatun osan ohjelmistoa**

---

## 3. Asiakasyhteistyö iteraatioissa
Iteratiivisen kehityksen keskeinen etu on jatkuva palaute:

- Asiakas näkee ohjelmiston tilan **jokaisen iteraation jälkeen**  
- Asiakas voi **muuttaa vaatimuksia**, tarkentaa tarpeita ja vaikuttaa seuraavan iteraation suuntaan  
- Ohjelmistosta voidaan julkaista **ensimmäinen käyttökelpoinen versio** jo kehitystyön aikana

Iteratiivinen malli ratkaisee näin vesiputousmallin keskeisimmän ongelman:  
asiakas ei osaa määritellä kaikkea etukäteen.

---

## 4. Roycen rooli ja väärinkäsitys
Winston Royce esitteli 1970 artikkelissaan lineaarisen vesiputousmallin, mutta:

> Royce EI suositellut vesiputousmallin käyttöä monimutkaisiin projekteihin.

Roycen todellinen suositus:
- tee **ensin prototyyppi**  
- opi siitä  
- tee **lopullinen järjestelmä toisessa iteraatiossa**

Roycen malli oli **iteratiivinen**, mutta ei täysin inkrementaalinen  
(koska ensimmäisessä vaiheessa tehtiin vain prototyyppi, ei oikeaa tuotetta).

---

## 5. Standardit ja virallinen tuki iteratiivisuudelle
Yhdysvaltain puolustusministeriö (DoD) julkaisi vuonna 2000 standardin **MIL-STD-498**, joka suosittelee nimenomaisesti iteratiivista kehitystä:

> “An evolutionary (iterative) approach is preferred… software development shall follow an iterative spiral development process…”

Tämä oli merkittävä muutos, koska DoD oli aiemmin vesiputousmallin tärkein tukija.

---

## 6. Iteratiivisen kehityksen historialliset juuret
Iteratiivinen ohjelmistokehitys on **vanhempi kuin vesiputousmalli**:

- NASA:n **Project Mercury** (1950-luvun lopulla) kehitettiin iteratiivisesti  
- Avaruussukkulan ohjelmisto (1970-luvun lopussa) tehtiin alkuperäisestä suunnitelmasta poiketen **8 viikon iteraatioissa**, yhteensä 31 kuukauden ajan  
- Larman & Basili dokumentoivat tämän historiassa “**Iterative and Incremental Development: A Brief History**”

Iteratiivisuus ei siis ole uusi ajatus – se on ollut toimivaksi todistettu jo varhain.

---

## 7. Yhteenveto
- Iteratiivinen malli vastaa vesiputousmallin ongelmiin.  
- Työ jaetaan lyhyisiin **iteraatioihin**, joissa tehdään kaikki kehityksen vaiheet.  
- Malli on **inkrementaalinen**: ohjelmisto kasvaa pala palalta.  
- Asiakas näkee ohjelmiston tilan usein ja voi muuttaa vaatimuksia.  
- Royce itse kannatti iteratiivisuutta jo 1970, vaikka hänen mallinsa myöhemmin tulkittiin väärin vesiputousmalliksi.  
- Myös DoD siirtyi suosimaan iteratiivisia menetelmiä.  
- Iteratiiviset mallit ovat olleet käytössä jo 1950-luvulta lähtien.

Iteratiivinen ja inkrementaalinen kehitys muodostavat perustan nykyisille ketterille menetelmille.

# Tiivistelmä: Ketterä ohjelmistokehitys

## 1. Tausta: Miksi ketteryys syntyi?
1980–1990-luvuilla ohjelmistokehitystä hallitsivat raskaat prosessimallit, joissa korostettiin:
- tarkkaa projektisuunnittelua  
- formaalia laadunvalvontaa  
- yksityiskohtaista analyysia ja suunnittelua  
- tiukasti ohjattuja prosesseja  

Nämä mallit toimivat hyvin **suurissa ja pitkäkestoisissa projekteissa**, mutta olivat **liian jäykkiä pieniin ja keskisuuriin projekteihin**.

Perinteiset prosessit myös pyrkivät minimoimaan yksilön merkityksen ja pitivät kehittäjiä “tehdastyöläisinä”, joita voi vaihtaa ilman vaikutusta projektiin.

Tämä synnytti **ketterät menetelmät (agile methods)**, jotka korostavat:
- ihmisten välistä yhteistyötä  
- toimivaa ohjelmistoa  
- asiakasyhteistyötä  
- muutoksiin reagointia  

---

## 2. Ketterä manifesti (Agile Manifesto)
Vuonna 2001 17 ketteryyden pioneeria laati manifestin, joka sisältää neljä keskeistä arvoa:

1. **Yksilöt ja vuorovaikutus** yli prosessien ja työkalujen  
2. **Toimiva ohjelmisto** yli kattavan dokumentaation  
3. **Asiakasyhteistyö** yli sopimusneuvottelujen  
4. **Muutoksiin reagointi** yli suunnitelman noudattamisen  

Tärkeää: oikean puolen asiat eivät ole arvottomia, mutta vasemman puolen asiat ovat **arvokkaampia**.

Manifestin laatijoita ovat mm. Kent Beck, Robert Martin, Martin Fowler ja Ken Schwaber.

---

## 3. Ketterät periaatteet (12 periaatetta)
Manifestin lisäksi ketteryyttä ohjaa **12 periaatetta**, joista keskeiset ovat:

### 1. Varhainen ja jatkuva toimivan ohjelmiston toimitus
- Asiakasarvo on tärkein.  
- Toimivaa ohjelmistoa toimitetaan **viikoittain–kuukausittain**, mielellään vielä tiheämmin.  
- Projektin edistymisen ensisijainen mittari on:  
  **“Working software is the primary measure of progress.”**

### 2. Tiivis yhteistyö ja kasvokkain kommunikointi
- Liiketoiminnan edustajat ja kehittäjät työskentelevät **päivittäin yhdessä**.  
- Paras kommunikointi tapahtuu **kasvokkain**, ei dokumenttien kautta.

### 3. Muutokset ovat tervetulleita
- Asiakas saa muuttaa vaatimuksia **myös myöhään projektissa**.  
- Muutoksiin reagoiminen nähdään kilpailuetuna, ei ongelmana.

### 4. Itseohjautuvat ja motivoituneet tiimit
- Projektit rakennetaan motivoituneiden yksilöiden ympärille.  
- Tiimeille annetaan ympäristö ja tuki, ja heihin **luotetaan**.  
- Parhaat arkkitehtuurit ja suunnitelmat syntyvät **itseorganisoituvissa tiimeissä**, ei erillisissä analyytikko- ja arkkitehtiryhmissä.

### 5. Jatkuva parantaminen
- Tiimit pysähtyvät säännöllisesti miettimään, miten tehostaa toimintaansa.  
- Prosessia parannetaan jatkuvasti.

### 6. Yksinkertaisuus
- **“Simplicity – the art of maximizing the amount of work not done.”**  
- Ketterät menetelmät välttävät tarpeetonta dokumentaatiota, ylisuuria suunnitelmia ja ylimääräistä koodia (“varmuuden vuoksi” -rakennetta).

### 7. Tekninen laatu ja kestävä kehitystahti
- Laatu on keskeistä: huono sisäinen rakenne tuhoaa ketteryyden ja tekee muutoksista hitaita.  
- Tarvitaan riittävästi teknistä suunnittelua (ei koko suunnitelmaa etukäteen).  
- Kehitystahti tulee olla **kestävä**: jatkuvaa ylitöitä ja kiirettä vältetään.  
  → “tiimin tulisi pystyä jatkamaan samaa tahtia ikuisesti”.

---

## 4. Keskeinen ero perinteisiin malleihin
Ketterä kehitys hylkää ajatuksen:
- raskaasta alkuvaiheen vaatimusmäärittelystä  
- dokumenttikeskeisyydestä  
- tiukasta prosessiohjauksesta  
- asiakkaan hylkäämisestä projektin ajaksi  

Sen sijaan se painottaa:
- jatkuvaa asiakasyhteistyötä  
- pientä, valmista tuotetta usein  
- nopeaa reagointia ympäristön muutoksiin  
- tiimien autonomiaa ja työskentelytapojen itse kehittämistä

---

## 5. Yhteenveto
Ketterä ohjelmistokehitys syntyi vastareaktiona raskaille prosesseille ja korostaa:
- ihmisiä prosessien sijaan  
- toimivaa ohjelmistoa dokumenttien sijaan  
- yhteistyötä sopimusten sijaan  
- muutoksiin reagointia suunnitelman sijaan  

Ketteryyden ytimessä ovat:
- tiheät julkaisut  
- asiakkaan jatkuva mukanaolo  
- itseorganisoituvat tiimit  
- korkea laatu  
- jatkuva parantaminen  
- yksinkertaisuus  
- kestävä työtahti  

Nämä periaatteet muodostavat nykyisen, laajasti käytetyn ohjelmistokehityksen perustan.

# Tiivistelmä: Ketterät menetelmät ja Lean

## 1. Ketterät menetelmät sateenvarjoterminä
Ketterät menetelmät (agile methods) eivät ole yksi menetelmä, vaan **kokonaisuus erilaisia lähestymistapoja**.  
2000-luvun alussa suosituin menetelmä oli **Extreme Programming (XP)**.

- Nykyään XP:tä ei käytetä “oppikirjamaisena” kokonaisuutena.  
- Sen käytänteet (esim. testivetoisuus, jatkuva integraatio) ovat kuitenkin jääneet **osaksi monien tiimien arkea**.

Kurssilla tutustutaan XP:n käytänteisiin tarkemmin.

---

## 2. Scrum – ketterien menetelmien valtavirta
XP:n tilalle keskeiseksi menetelmäksi on noussut **Scrum**, joka on nykyisin maailman käytetyin ohjelmistokehitysmenetelmä.  
Seuraavassa luvussa syvennytään Scrumiin tarkemmin.

---

## 3. Lean ja agile – yhteinen taustafilosofia
Ketterä ohjelmistokehitys on saanut runsaasti vaikutteita **lean-ajattelusta**, joka tunnetaan erityisesti Toyota Production Systemistä.

Lean-ajattelun keskeisiä ideoita ohjelmistokehityksessä:
- hukan minimointi  
- jatkuva parantaminen  
- työn virtaavuuden optimointi  

Lean liittyy agileen niin tiiviisti, että nykyään ne esiintyvät usein **rinnakkain tai päällekkäisinä** termeinä.

### Kanban
Leanista peräisin oleva **kanban** on yleistynyt ohjelmistokehityksessä.  
Usein sitä **yhdistetään Scrumiin**, ja yhdistelmä tunnetaan nimellä **Scrumban**.

Lean-ajattelua käsitellään tarkemmin kurssin osassa 5.

---

## 4. Ketteryyden skaalaaminen isompiin organisaatioihin
Alun perin ketterät menetelmät suunniteltiin **pienille, yksit**


# Tiivistelmä: Scrumin taustat ja vesiputousmallin ongelmat

## 1. Scrum – ketterien menetelmien yleisin edustaja
Scrum on nykyään käytetyin ketterä ohjelmistokehitysmenetelmä.  
Ennen Scrumiin siirtymistä on hyödyllistä ymmärtää, miksi perinteinen vesiputousmalli ja jopa varhaiset iteratiiviset mallit eivät toimineet riittävän hyvin.

---

## 2. Vesiputousmallin keskeiset ongelmat

### 1. Vaatimuksia ei voi määritellä täydellisesti alussa
- Asiakkaat eivät yleensä projektin alussa tiedä tarkkaan mitä haluavat.  
- Bisnesympäristö ja tarpeet muuttuvat projektin aikana.  
→ Siksi pitkäaikaiset ja “lukitut” vaatimusmäärittelyt eivät toimi.

### 2. Suunnittelua ei voi tehdä niin täydellisesti, että ohjelmointi olisi mekaaninen rakennusvaihe
- Ohjelmointi EI ole sama asia kuin talon rakentaminen.  
- Suunnittelua ei voi ennustaa etukäteen täydellisesti.  
- Ohjelmointi sisältää tutkimista, ongelmanratkaisua ja kokeilua.

### 3. Ohjelmointi on osa suunnittelua – koodi on lopullinen suunnitelma
- Ohjelmakoodi **itsessään** on tarkin ja todellinen suunnitelma tuotteesta.  
- “Suunnittele kaikki ennakkoon” -ajattelu ei toimi ohjelmistokehityksessä.

### 4. Myöhäinen testaus paljastaa virheet liian myöhään
- Vesiputousmallissa testaus tehdään vasta lopuksi.  
- Jos virheet liittyvät arkkitehtuuriin tai vaatimuksiin, niiden korjaaminen on erittäin kallista.  

---

## 3. Miksi iteratiiviset mallitkaan eivät riittäneet?
1990-luvulla kehitetyt iteratiiviset prosessit korjasivat monia vesiputousmallin ongelmia, mutta niissä oli edelleen:

- vahva **suunnitelmavetoinen** (plan-based) ajattelu  
- oletus, että prosessia voi kontrolloida tarkasti  
- raskas roolijako: projektipäälliköt, analyytikot, arkkitehdit, ohjelmoijat ja testaajat toimivat omissa siiloissaan

Vaikka iteratiiviset mallit paransivat tilannetta, ne eivät vielä vastanneet nopean muutoksen, epävarmuuden ja oppimisen tarpeisiin — ja tästä syystä Scrum ja muut ketterät menetelmät nousivat esiin.

---

## 4. Yhteenveto
- Vesiputousmalli kaatuu siihen, että vaatimukset muuttuvat, suunnittelu on epävarmaa ja testaus tapahtuu liian myöhään.  
- Iteratiiviset mallit korjasivat osan ongelmista, mutta olivat yhä liian suunnitelmavetoisia ja hierarkkisia.  
- Scrum rakentuu juuri näiden ongelmien ratkaisemiseksi korostamalla joustavuutta, tiimivetoisuutta ja jatkuvaa palautetta.


# Tiivistelmä: Ketterien menetelmien perusolettamukset ja Scrumin tausta

## 1. Ketterien menetelmien perusolettamukset

### Ohjelmistoprojektit ovat aina osittain uniikkeja
- Jokaisen projektin **vaatimukset, ihmiset ja teknologiat** ovat erilaisia.  
- Kehittäjät vaihtuvat, tiimeillä on erilaiset osaamisprofiilit, ja teknologia muuttuu jatkuvasti.  
→ Tästä syystä ohjelmistokehitystä **ei voi suunnitella täysin etukäteen** kuten teollista tuotantoa.

### Ohjelmistokehitys ei ole kontrolloitu prosessi, vaan tuotekehitystä
- Projekteissa on paljon **epävarmuutta** ja tuntemattomia muuttujia.  
- Siksi ketterät menetelmät perustuvat **empiiriseen prosessiin**, ei ennustavaan suunnitelmaan.

### Empiirinen prosessi perustuu kolmeen periaatteeseen:
1. **Transparency (läpinäkyvyys)**  
   – Kaikkien tiimin jäsenten tulee ymmärtää, mitä tehdään ja mitä “valmis” tarkoittaa.  
2. **Inspection (tarkkailu)**  
   – Tiimi seuraa jatkuvasti, ovatko tuotteen suunta ja työskentelytavat oikeita.  
3. **Adaptation (mukautuminen)**  
   – Kun havaitaan poikkeamia tai uusia tarpeita, toimintaa muutetaan heti.

### Ketterä näkemys ihmisistä ja tiimeistä
- Perinteinen **command-and-control** ja tiukka roolijako (suunnittelija, ohjelmoija, testaaja, backend, frontend…) ei toimi optimaalisesti.  
- Ketterät menetelmät luottavat **itseorganisoituviin tiimeihin**, jotka:  
  - saavat työrauhan  
  - vastaavat itse omasta toiminnastaan  
  - onnistuvat ja epäonnistuvat kollektiivisesti

---

## 2. Scrumin tausta

### Alkuperä
- Termi **Scrum** esiintyi ensimmäisen kerran Takeuchin ja Nonakan (1986) artikkelissa *The New New Product Development Game*, jossa kuvattiin menestyvien yritysten yhteisiä toimintatapoja.  

### Nykyinen Scrum
- Nykyisen Scrumin loivat **Ken Schwaber** ja **Jeff Sutherland** 1990-luvun puolivälissä.  
- Scrumia määrittelee **The Scrum Guide** (n. 20 sivua), jonka viimeisin versio on vuodelta 2020.

### Scrumin määritelmä
Scrumin kehittäjien mukaan:

> **“Scrum is a framework within which people can address complex adaptive problems, while productively and creatively delivering products of the highest possible value.”**

Keskeistä:
- Scrum on **framework**, ei tarkka prosessi tai valmis menetelmä.  
- Se antaa *raamit*, mutta tiimin on itse täytettävä ne sopivilla käytännöillä ja tekniikoilla.

### Scrumin tavoitteet ja ydinarvot
Scrum pyrkii tekemään näkyväksi:
- tiimin tuottaman arvon  
- työn kulun  
- käytettyjen menetelmien toimivuuden  

Keskiössä ovat jälleen:
- **Transparency (läpinäkyvyys)**  
- **Inspection (tarkkailu)**  
- **Adaptation (mukautuminen)**  

### Scrumin luonne
Scrum on:
- **Lightweight** – sisältää vähän sääntöjä  
- **Simple to understand** – Scrum Guiden voi lukea puolessa tunnissa  
- **Extremely difficult to master** – tehokas käyttö vaatii syvällistä ymmärrystä ja kokemusta

Pelkkä sääntöjen mekaaninen noudattaminen ei tee tiimistä ketterää — Scrum toimii vain, jos sen taustafilosofia todella omaksutaan.

---

## 3. Yhteenveto
- Ketterät menetelmät lähtevät oletuksesta, että ohjelmistokehitys on epävarmaa tuotekehitystä, ei suunnitelmalla kontrolloitava prosessi.  
- Empiirinen prosessi (transparency, inspection, adaptation) on ketteryyden ydin.  
- Itseorganisoituvat tiimit ovat tehokkaampia kuin tiukat roolit ja komentoketjut.  
- Scrum on suosituin ketterä framework: kevyt rakenteeltaan mutta vaativa hallita.  
- Scrumin tarkoitus on tehdä työ näkyväksi ja mahdollistaa jatkuva parantaminen.


# Tiivistelmä: Scrum lyhyesti

## 1. Scrum yleiskuva
Scrum on **iteratiivinen ja inkrementaalinen** ketterä menetelmäkehys, jossa kehitys tapahtuu **1–4 viikon mittaisissa sprinteissä**.  
Tiimi toimittaa jokaisen sprintin lopussa **toimivan, julkaistavissa olevan ohjelmiston osan** (increment).

---

## 2. Scrumin roolit
Scrumissa on kolme roolia:

### **1. Product Owner (PO)**
- Hallinnoi ja priorisoi **product backlogia**  
- Päättää, mitä kehitetään ja missä järjestyksessä  
- Kommunikoi sidosryhmien kanssa  
- Varmistaa, että tiimi ymmärtää vaatimukset  

### **2. Scrum Master**
- Ei ole projektipäällikkö, vaan **valmentaja ja fasilitaattori**  
- Auttaa tiimiä noudattamaan Scrumia  
- Poistaa esteitä (teknisiä, organisatorisia, kommunikatiivisia)  
- Suojaa tiimiä häiriöiltä  
- Edistää itseorganisoitumista  

### **3. Developer / kehittäjätiimi**
- 3–9 henkilöä  
- Cross-functional: sisältää kaiken osaamisen suunnitteluun, toteutukseen, testaukseen ja operointiin  
- Itseorganisoituva: tiimi päättää **miten** sprintin tavoitteet toteutetaan  
- Koko tiimi kantaa **yhteisvastuun** lopputuloksesta  

---

## 3. Scrumin artefaktit
### **Product Backlog**
- Priorisoitu lista vaatimuksista ja ominaisuuksista  
- Sisältää myös refaktorointeja, teknisiä töitä ja bugikorjauksia  
- Backlogin kärki on tarkemmin määritelty kuin häntä  
- PO vastaa backlogista  

### **Sprint Backlog**
- Sprinttiin valitut backlog-asiat + tiimin laatimat tehtävät  
- On **tiimin sisäinen työkalulista**, teknisellä tasolla  

### **Increment**
- Sprintin lopuksi syntyvä **valmis**, julkaistavissa oleva ohjelmiston osa

---

## 4. Definition of Done (DoD)
- Yhteinen määritelmä sille, mitä “valmis” tarkoittaa  
- Sisältää tyypillisesti: analysoitu, suunniteltu, koodattu, testattu, dokumentoitu, integroitu, automaatiot kunnossa  
- Jos vaatimus ei täytä DoD:tä sprintin lopussa → se ei ole valmis ja siirretään takaisin backlogiin  
- Estää “melkein valmiin” työn kertymisen ja tukee laatua

---

## 5. Sprintti
- Pituus 1–4 viikkoa, **yleisimmin 2 viikkoa**  
- **Time-boxed**: kestoa ei muuteta kesken sprintin  
- Tiimi valitsee sprinttiin vain sen, mihin se realistisesti ehtii  
- Sprintin lopussa on oltava **toimiva versio ohjelmistosta**

Sprintin aikana:
- Ei oteta uusia tehtäviä sprinttiin ulkopuolelta  
- Scrum Master suojaa tiimiä häiriöiltä  

---

## 6. Scrumin eventit (seremoniat)

### **1. Sprint Planning**
- Ennen sprintin alkua  
- PO esittelee tärkeimmät backlog-asiat  
- Tiimi valitsee toteutettavat asiat  
- Määritetään **Sprint Goal** (sprintin tavoite)  
- Tiimi suunnittelee toteutuksen ja laatii Sprint Backlogin  

### **2. Daily Scrum**
- Joka päivä, max 15 min  
- Tavoite: **tarkastella edistystä ja suunnitella seuraavan 24h työ**  
- Ei vain statuspalaveri – osa Scrum “inspect & adapt” -sykliä  
- Tiimi voi käyttää mitä tahansa rakennetta, kunhan se keskittyy Sprint Goal -tavoitteeseen

### **3. Sprint Review**
- Sprintin lopussa  
- Tiimi demonstroi **valmiin ohjelmiston** (ei PowerPointia!)  
- Sidosryhmät antavat palautetta  
- PO hyväksyy tai hylkää tehtävät  
- Backlogia voidaan päivittää ja priorisoida uudelleen  

### **4. Sprint Retrospective**
- Tiimi tarkastelee omaa toimintaa  
- Tavoite: löytää parannuksia, korjata ongelmia  
- Osa Scrumin *inspect & adapt* -mekanismia

---

## 7. Scrumin periaatteet: Transparency – Inspection – Adaptation
Nämä kolme periaatetta muodostavat Scrumin ytimen:

### **Transparency**
- Kaikilla on yhteinen käsitys työstä, DoD:stä, edistymisestä  
- Tiedot ovat avoimia ja näkyviä

### **Inspection**
- Sprintin tapahtumia ja tuotteen kehitystä tarkastellaan jatkuvasti  

### **Adaptation**
- Suunnanmuutokset tehdään heti, jos havaitaan poikkeamia  
- Sovelletaan sekä tuotteeseen että prosessiin

---

## 8. Scrumin arvot
Scrumin toiminta nojaa viiteen arvoon:

- **Commitment** (sitoutuminen)  
- **Courage** (rohkeus)  
- **Focus** (keskittyminen)  
- **Openness** (avoimuus)  
- **Respect** (kunnioitus)

Nämä arvot luovat “hedelmällisen maaperän” (fertile soil) tehokkaalle ohjelmistokehitykselle ja mahdollistavat oikean ketterän ajattelutavan.

---

## 9. Yhteenveto
Scrum on kevyt mutta vaativa menetelmäkehys, jossa:
- tiimit toimivat itseorganisoidusti  
- tuotteesta toimitetaan toimiva versio jokaisessa sprintissä  
- PO ohjaa mitä kehitetään  
- Scrum Master ohjaa miten kehitetään ja poistaa esteitä  
- läpinäkyvyys, tarkkailu ja mukautuminen ohjaavat jatkuvaa parantamista  

Se on yksinkertainen ymmärtää, mutta **vaikea hallita** – todellinen tehokkuus vaatii syvän osaamisen ja oikean ajattelutavan.

# Tiivistelmä: Scrumin ongelmat

## Scrum ei ole täydellinen ratkaisu
Scrum on parannus vesiputousmalliin verrattuna, mutta ei ratkaise kaikkia ongelmia. Scrumin käytön yleistyessä myös epäonnistumisten määrä kasvaa.

---

## 1. ScrumBut – Scrumin väärin soveltaminen
ScrumBut = “Käytämme Scrumia, mutta…”  
Esimerkkejä:
- Daily Scrum vain kerran viikossa  
- Ei retrospektiivejä  
- Sprintin pituus 3 kuukautta  

-> Johtaa Scrumin ydinperiaatteiden (läpinäkyvyys, tarkkailu, mukautuminen) heikkenemiseen.

---

## 2. Haasteet tietyissä ympäristöissä
Scrum ei toimi yhtä hyvin, kun:
- Työ on **hajautettua**
- On **paljon alihankkijoita**
- Projekti on **hyvin suuri**
- Tiimejä on **monta**

---

## 3. Uncle Bob Martin – keskeinen kritiikki

### **a. Ei teknisiä käytäntöjä**
Scrum on projektinhallintaa, ei kerro:
- miten testataan  
- miten varmistetaan koodin laatu  
- miten estetään tekninen velka  

-> Ilman automaattista testausta sprintit eivät voi olla oikeasti lyhyitä.  
-> Laatu voi romahtaa, ketteryys katoaa.

### **b. Scrum Master -ongelmat**
- CSM-sertifikaatti (Certified Scrum Master) on liian kevyt  
- Scrum Masterit voivat käytännössä toimia projektipäälliköinä → mikromanageeraus  
- Toisinaan rooli muuttuu vain uudeksi titteliksi ilman todellista muutosta

### **c. Liiallinen usko itseorganisoitumiseen**
- Toimii vain osassa tiimejä  
- Ei riitä, jos projekti on monimutkainen tai tiimejä on useita  
- Vaatii enemmän koordinaatiota kuin Scrum ohjeistaa

### **d. Backlogin hallintaan ei tarjota riittävästi ohjeita**
- Monimutkaisten tuotteiden pilkkominen on vaikeaa  
- Scrum jättää product ownerin usein yksin tämän haasteen kanssa

### **e. Sprinttien kesto**
- 30 päivän sprintti on liian pitkä  
- Lyhyet sprintit vaativat teknisiä käytäntöjä, joita Scrum ei määrittele

---

## 4. Scaling: Scrum ei skaalaudu itsestään
Scrum antaa vähän ohjeita monitiimisten projektien hallintaan.  
Siksi syntyi menetelmiä kuten:
- **SAFe**
- **LeSS**
- **Nexus**

Ne paikkaavat puutteita, mutta herättävät myös kritiikkiä (esim. SAFe ei joidenkin mielestä ole “oikeasti ketterä”).

---

## 5. Organisaatiotason ongelmat
Yleinen kompastuskivi: muu organisaatio ei muutu.

Tuloksena syntyy **waterscrumfall**:
- tiimit tekevät Scrumia  
- mutta budjetointi, vaatimusten hallinta ja tuotantoonvienti noudattavat edelleen vesiputousmallia  

-> Kombinaatio toimii huonosti ja aiheuttaa kitkaa.

---

## 6. Scrum on helppo ymmärtää – vaikea hallita
> “Scrum is easy to understand but extremely difficult to master.”

Scrumin säännöt ovat yksinkertaisia, mutta niiden oikea soveltaminen vaatii:
- vahvoja teknisiä käytäntöjä  
- hyvää tiimikulttuuria  
- organisaation tukea  
- korkeaa kurinalaisuutta  
- osaavia Scrum Mastereita ja Product Ownereita  

Scrum epäonnistuu usein, kun yksi näistä puuttuu.

