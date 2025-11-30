# Laadunhallinnan tiivistelmä: verifiointi, validointi, katselmoinnit, testaus ja DevOps

## 1. Verifiointi ja validointi (V&V)

### **Verifiointi** – *"Rakennammeko tuotteen oikein?"*  
- Tarkistaa, että ohjelmisto **täyttää sille määritellyt vaatimukset**.  
- Perustuu yleensä **testaukseen** ja dokumenttien tarkistamiseen.  
- Kohdistuu toiminnallisiin ja ei-toiminnallisiin vaatimuksiin.

### **Validointi** – *"Rakennammeko oikean tuotteen?"*  
- Tarkistaa, että ohjelmisto **vastaa käyttäjän todellista tarvetta**.  
- Vaatimukset voivat olla virheellisiä → validointi paljastaa nämä.  
- Vesiputousmallissa tehdään katselmoinneilla; ketterässä demoilla (sprint review).

### **Laadunhallinta (QA)**  
Verifiointi + validointi = laadunhallinta.  
Jos vastuussa on erillinen tiimi → **QA-tiimi**.

---

## 2. Katselmoinnit ja tarkastukset

### **Katselmointi (review)**
- Staattinen tekniikka (ei ajeta ohjelmaa).
- Käydään läpi koodi tai dokumentit → etsitään virheitä ja parannuskohteita.

### **Tarkastus (inspection)**
- Katselmoinnin formaalimpi versio.  
- Käytetään lähinnä **turvallisuuskriittisissä** järjestelmissä.

### **Staattinen analyysi**
- Automaattinen koodin tarkistus ilman suoritusta.  
- Esim. **ESLint**, **Pylint**, **SonarQube**, **Codacy**, **Qlty**.  
- Havaitsee: monimutkaisuuden, kopioidun koodin, tyylirikot, tietoturvariskit.

### **Pull request -katselmointi**
- GitHub-pull requestit mahdollistavat katselmoinnit ennen koodin yhdistämistä.  
- Kehittäjät antavat kommentteja ja parannusehdotuksia.  
- Yhä useammin osa "definition of done" -prosessia.

### **AI koodikatselmoinnissa**
- GitHub Copilot voi ehdottaa korjauksia ja kommentoida pull requesteja.

---

## 3. XP:n katselmointikäytännöt

### **Pariohjelmointi (pair programming)**
- Kaksi kehittäjää yhdellä koneella:  
  - *Driver* kirjoittaa koodia  
  - *Navigator* tarkastaa ja suunnittelee  
- Tarkastus tapahtuu jatkuvasti.

### **Collective code ownership**
- Kaikki kehittäjät voivat muokata mitä tahansa koodin osaa.

### **Coding standards**
- Tiimin yhteinen **koodityyli** (nimeäminen, rakenteet, formatointi).  
- Automaattisesti valvottavissa esim. ESLint/Pylint.

---

## 4. Testauksen peruskäsitteet

### **Testauksen tavoitteet**
1. Varmistaa, että ohjelma täyttää vaatimukset.  
2. Löytää virheitä ennen käyttäjiä.  
→ Parantaa ohjelmiston **ulkoista laatua** (external quality).

### **Testauksen tasot**
- **Yksikkötestaus (unit testing):** yksittäiset metodit/luokat.  
- **Integraatiotestaus:** komponenttien yhteistoiminta.  
- **Järjestelmätestaus (system testing):** koko sovellus käyttäjän näkökulmasta.  
  - **Black box** ja **end-to-end**-testaus.  
- **Käyttäjän hyväksymistestaus (UAT):** asiakkaan varmistus, että sovellus täyttää odotukset.

### **Testitapausten valinta**
- Kaikkia yhdistelmiä ei voi testata → käytetään:
  - **Ekvivalenssiluokat**: syötteet jaetaan ryhmiin, joissa järjestelmä toimii samalla tavalla.
  - **Raja-arvot**: testataan kriittiset ääripäät, joissa virheet usein piilevät.

---

## 5. Yksikkötestaus ja testauskattavuus

### **White box -testaus**
- Testataan koodin sisäisen rakenteen perusteella (ehtolauseet, polut).

### **Testauskattavuus**
- **Rivikattavuus:** monta prosenttia riveistä suoritettiin.  
- **Haarautumakattavuus:** ehtolauseiden oksien kattavuus.  
- Kattavuus mittaa testien laajuutta, mutta ei kerro niiden laadusta.

### **Mutaatiotestaus**
- Koodiin luodaan pieniä tahallisia virheitä → testien kuuluu löytää ne.  
- Testaa **testien laatua**, ei ohjelman laatua.

---

## 6. Integraatiotestaus ja regressiotestaus

### **Integraatiotestaus**
- Testataan komponenttien rajapintoja ja yhteistyötä.  
- Voi olla rakenteellinen tai toiminnallinen.

### **Regressiotestaus**
- Suoritetaan aina, kun koodia muutetaan.  
- Varmistaa, että vanha toiminnallisuus ei rikkoudu.  
- Tarvitsee laajan **automatisoitujen testien** joukon.

---

## 7. Testaus ketterissä menetelmissä

### **Pääperiaatteet**
- Testaus on osa päivittäistä työtä, ei erillinen vaihe.  
- Testit kirjoitetaan usein heti storyn alussa.  
- Painotus automatisoiduissa regressiotesteissä.

### **Test Driven Development (TDD)**
- Testi → koodi → refaktorointi.  
- Sykli: **red → green → refactor**.  
- Tuottaa modulaarista ja selkeää koodia.

### **Riippuvuuksien hallinta testeissä**
- Käytetään **stubeja** ja **mockeja** simuloimaan riippuvuuksia.  
- Kirjastot: esim. Pythonin `unittest.mock`.

### **User storyjen hyväksymistestit**
- Hyväksymiskriteerit → toiminnallisia end-to-end-testejä.  
- Pääulostulo: käyttäjän kielinen kuvaus odotetusta käytöksestä.

---

## 8. ATDD, BDD ja Robot Framework

### **ATDD – Acceptance Test Driven Development**
- Hyväksymistason testit kirjoitetaan ennen toteutusta.

### **BDD – Behavior Driven Development**
- Testien kuvaus käyttäjän kielellä “käyttäytymisenä”.  
- Esim. *Given–When–Then*.

### **Robot Framework**
- Suomalainen testiautomaatiotyökalu.  
- Testit kirjoitetaan luonnollisella kielellä → helposti luettavia.

---

## 9. Jatkuva integraatio ja toimitus

### **Daily build + smoke test**
- Päivittäinen koko sovelluksen käännös ja perustoimintojen testi.

### **Continuous Integration (CI)**
- Jokainen muutos integroidaan päähaaraan vähintään päivittäin.  
- CI-palvelin kääntää ja testaa koodin automaattisesti.  
- Työkalut: GitHub Actions, Jenkins, Travis, CircleCI.

### **Continuous Delivery**
- Uusi versio aina valmiina vietäväksi tuotantoon.

### **Continuous Deployment**
- Jokainen onnistunut buildi → automaattisesti tuotantoon.

---

## 10. Tuotannossa testaaminen

### **Blue-green deployment**
- Kaksi tuotantoympäristöä (blue & green).  
- Uusi versio testataan passiivisessa ympäristössä → roolit vaihdetaan.

### **Canary release**
- Uusi versio tarjotaan ensin pienelle käyttäjäryhmälle (esim. 5%).  
- Versiota monitoroidaan → laajennetaan jos ei ongelmia.

### **Feature toggles**
- Ominaisuus voidaan kytkeä päälle/pois ilman koodin uudelleenasennusta.  
- Mahdollistaa A/B-testauksen, canary release -työskentelyn ja jatkuvan julkaisemisen.

---

## 11. Versionhallinta ja kehitysmallit

### **Feature branch -malli**
- Jokainen ominaisuus omassa haarassaan.  
- Vaarana: **merge hell** (konflikteja, isoja yhdistämisiä).

### **Trunk-based development**
- Kaikki koodi tehdään suoraan päähaaraan.  
- Pienet, nopeat commitit.  
- Feature togglet estävät keskeneräisten ominaisuuksien näkymisen käyttäjille.

---

## 12. DevOps

### **DevOps-kulttuuri**
- Dev (kehittäjät) + Ops (ylläpito) → yhteinen vastuu tuotannosta.  
- Tavoite: nopea ja luotettava tuotantoonvienti.

### DevOps-tyypilliset työkalut:
- Automatisoitu testaus  
- CI/CD  
- Kontit (Docker)  
- Infrastructure as Code  
- Pilvipalvelut (PaaS, IaaS, SaaS)

---

## 13. Agile Testing Quadrants

Neljä testauksen kategoriaa:

- **Q1 – Technology-facing, team-supporting**  
  Yksikkötestit, komponenttitestit

- **Q2 – Business-facing, team-supporting**  
  ATDD, BDD, hyväksymistestit

- **Q3 – Business-facing, product-criticizing**  
  Exploratory testing, UAT

- **Q4 – Technology-facing, product-criticizing**  
  Suorituskyky, tietoturva, kuormitustestit

Kaikilla on roolinsa eri tilanteissa.

---

## 14. Yleisiä päätelmiä laadunhallinnasta

- Testauksen tavoitteena on **maksimoida asiakkaalle tuotettu arvo**, ei koodin täydellinen virheettömyys.  
- Testauksen automatisointi kannattaa, mutta **väärien testien automatisointi on kallista**.  
- End-to-end -testit ovat arvokkaita mutta kalliita ylläpitää.  
- Usein kannattaa tehdä:
  - vähemmän UI-testejä  
  - enemmän integraatiotason testejä  
  - hyvin valittuja yksikkötestejä  

### Kriittisin tekijä laadun kannalta:
**Nopeat ja usein toistuvat tuotantoonviennit (CI/CD + trunk-based dev).**

Ne estävät integraatio-ongelmat ja tekevät laadusta näkyvää.

---

## 15. Tutkimusnäyttö

Forsgrenin, Humblen ja muiden tutkimukset (Accelerate, 2018):

- DevOps-käytännöt → parempi organisaation tehokkuus  
- Sisältää: CI, CD, testiautomaatio, trunk-based dev, monitorointi  
- Tuloksena:  
  - parempi tuottavuus  
  - lyhyempi toimitusaika  
  - parempi laatu  
  - tyytyväisemmät työntekijät

