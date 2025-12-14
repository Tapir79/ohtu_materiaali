class Kurssi:
    def __init__(self, nimi, vuosi):
        self.__nimi = nimi
        self.__vuosi = vuosi
        self.__palautteet = []

        # haetaan palautteet tiedostosta
        try:
            with open(nimi + ".csv") as tiedosto:
                for rivi in tiedosto:
                    osat = rivi.split(";")
                    self.__palautteet.append({
                        "opiskelija": osat[0], 
                        "arvosana": int(osat[1]), 
                        "kommentti": osat[2]
                    })
        except:
            pass
    
    # lisätään uusi kurssipalaute, onnistuu vaan jos opiskelija ei ole antanut palautetta
    def anna_palaute(self, uusi_palaute):
        for p in self.__palautteet:
            if p["opiskelija"] == uusi_palaute["opiskelija"]:
                return False
            
        kommentti = uusi_palaute["kommentti"] if "kommentti" in uusi_palaute else ""

        self.__palautteet.append({
            "opiskelija": uusi_palaute["opiskelija"], 
            "arvosana": uusi_palaute["arvosana"], 
            "kommentti": kommentti
        })

        with open(self.__nimi + ".csv", "w") as tiedosto:
            for p in self.__palautteet:
                tiedosto.write(f"{p['opiskelija']};{p['arvosana']};{p['kommentti']};\n")

        return True
    
    def muuta_palautetta(self, muutettu_palaute):
        for p in self.__palautteet:
            if p["opiskelija"] == muutettu_palaute["opiskelija"]:
                kommentti = muutettu_palaute["kommentti"] if "kommentti" in muutettu_palaute else ""

                p["arvosana"] = muutettu_palaute["arvosana"]
                p["kommentti"] = kommentti

                with open(self.__nimi + ".csv", "w") as tiedosto:
                    for p in self.__palautteet:
                        tiedosto.write(f"{p['opiskelija']};{p['arvosana']};{p['kommentti']}:\n")

                return True

        return False
    
    def hae_palaute(self, opiskelija):
        for p in self.__palautteet:
            if p["opiskelija"] == opiskelija:
                return p

        return None
    
    def hae_kommentin_sisaltavat_palautteet(self):
        palautteet = []
        for palaute in self.__palautteet:
            if len(palaute["kommentti"]) > 0:
                palautteet.append(palaute)
        
        return palautteet

    def hae_palautteet_joiden_arvosana(self, x):
        palautteet = []
        for palaute in self.__palautteet:
            if palaute["arvosana"] == x:
                palautteet.append(palaute)
        
        return palautteet

    def hae_palautteet_joiden_arvosana_valilla(self, x, y):
        palautteet = []
        for palaute in self.__palautteet:
            if palaute["arvosana"] >= x and palaute["arvosana"] <= y:
                palautteet.append(palaute)
        
        return palautteet

    def yhteenveto(self):
        print(f"{self.__nimi}, {self.__vuosi}")
        print("============")
        print("palautteita annettiin", len(self.__palautteet), "kappaletta")
        
        x = 0
        for palaute in self.__palautteet:
            x += palaute["arvosana"]
        
        print("keskiarvo ", x/ len(self.__palautteet))

        print()
        print("jakauma")
    
        x = 0
        # tulostetaan ilman rivinvaihtoa
        print("5: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == 5:
                print("*", end="")
        print()

        x = 0
        print("4: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == 4:
                print("*", end="")
        print()
       
        x = 0
        print("3: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == 3:
                print("*", end="")
        print()

        x = 0
        print("2: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == 2:
                print("*", end="")
        print()

        x = 0
        print("1: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == 1:
                print("*", end="")
        print()

        print()
        print("kommentit")
                
        for palaute in self.__palautteet:
            if len(palaute["kommentti"]) > 0:
                print("  " + palaute["kommentti"])


# testipääohjelma
ohtu = Kurssi("ohtu", 2023)
ohtu.anna_palaute({ "opiskelija": "01234567", "arvosana": 4, "kommentti": "hyvät laskarit" })
ohtu.anna_palaute({ "opiskelija": "01234567", "arvosana": 2, "kommentti": "paska koe" })
ohtu.muuta_palautetta({ "opiskelija": "01234567", "arvosana": 2, "kommentti": "paska koe" })
ohtu.anna_palaute({ "opiskelija": "01231221", "arvosana": 4 })
ohtu.anna_palaute({ "opiskelija": "01234561", "arvosana": 3, "kommentti": "miniprojekti rocks" })
ohtu.anna_palaute({ "opiskelija": "01234111", "arvosana": 1 })

ohtu.yhteenveto()