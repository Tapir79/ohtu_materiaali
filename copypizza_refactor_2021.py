import random

class Order:
    def __init__(self, customer_name: str, customer_address: str, ingredients):
        self.status = "ordered"
        self.customer = {
          "name": customer_name,
          "address": customer_address,
        }
        self.ingredints = ingredients

    def set_delivered(self):
        self.status = "delivered"

    def set_making(self):
        self.status = "making"

    def __str__(self):
        return f'{self.id} {self.status} {self.customer} {self.ingredints}'
    
class Tiedostokasittelija:

    def lue_tiedosto(self, tiedostonimi):
        orders = []
        with open(tiedostonimi, "r") as file:
            for row in file:
                parts = row.strip().split(";")
                order = Order(parts[2], parts[3], parts[4].split(','))
                order.id = int(parts[0])
                order.status = parts[1]
                orders.append(order)
        return orders
    
    def kirjoita_tiedostoon(self, tiedostonimi, orders):
         with open(tiedostonimi, "w") as file:
            for order in orders:
                ingredients = ','.join(order.ingredints)
                file.write(f'{order.id};{order.status};{order.customer["name"]};{order.customer["address"]};{ingredients}\n')
    

class MatchEhtoStrategia:
    def ehto_tayttyy(self, order):
        """Palauttaa True jos tilaus täyttää ehdon"""
        raise NotImplementedError("Aliluokan tulee toteuttaa ehto_tayttyy-metodi")
    
class DeliveredStrategia(MatchEhtoStrategia):
    def ehto_tayttyy(self, order):
        return order.status == "delivered"
    
class NewOrderStrategia(MatchEhtoStrategia):
    def ehto_tayttyy(self, order):
        return order.status == "ordered"
    
class CustomerNameStrategia(MatchEhtoStrategia):
    def __init__(self, customer_name):
        self.customer_name = customer_name
    
    def ehto_tayttyy(self, order):
        return order.customer["name"] == self.customer_name
    
class IngredientStrategia(MatchEhtoStrategia):
    def __init__(self, ingredient):
        self.ingredient = ingredient
    
    def ehto_tayttyy(self, order):
        return self.ingredient in order.ingredints


class MarkEhtoStrategia:
    def suorita(self, order):
        """Suorittaa tilauksen tilan muutoksen"""
        raise NotImplementedError("Aliluokan tulee toteuttaa suorita-metodi")
    
class MarkDeliveredStrategia(MarkEhtoStrategia):
    def suorita(self, order):
        order.set_delivered()

class MarkMakingStrategia(MarkEhtoStrategia):
    def suorita(self, order):
        order.set_making()


class ExportStrategia:
    def tulosta_otsikko(self):
        """Tulostaa export-tiedoston otsikon"""
        pass
    
    def tulosta_tilaus(self, order):
        """Tulostaa yhden tilauksen"""
        raise NotImplementedError("Aliluokan tulee toteuttaa tulosta_tilaus-metodi")
    
    def tulosta_lopetus(self):
        """Tulostaa export-tiedoston lopetus"""
        pass


class XMLExportStrategia(ExportStrategia):
    def tulosta_otsikko(self):
        print('<orders>')
    
    def tulosta_tilaus(self, order):
        print("  <order>")
        print(f"    <id>{order.id}</id>")
        print(f"    <customer><name>{order.customer['name']}</name><address>{order.customer['address']}</address></customer>")
        print(f"    <numberOfIngredients>{len(order.ingredints)}</numberOfIngredients>")
        print("  </order>")
    
    def tulosta_lopetus(self):
        print('</orders>')


class TSVExportStrategia(ExportStrategia):
    def tulosta_tilaus(self, order):
        print(f"{order.id}\t{order.customer['name']}\t{order.customer['address']}\t{len(order.ingredints)}")


class CopyPizza:
    def __init__(self):
        self._kasittelija = Tiedostokasittelija()
        self._orders = self._kasittelija.lue_tiedosto("tilaukset.csv")

    def save(self):
        self._kasittelija.kirjoita_tiedostoon("tilaukset.csv", self._orders)


    def _list_ehto(self, order, ehto, matches):
        for order in self._orders:
            if ehto(order):
                matches.append(order)
        return matches

    def list_delivered(self):
        return self._list_ehto(self._orders, DeliveredStrategia().ehto_tayttyy, [])

    def list_new(self):
        return self._list_ehto(self._orders, NewOrderStrategia().ehto_tayttyy, [])

    def list_customer(self, customer_name: str):
        return self._list_ehto(self._orders, CustomerNameStrategia(customer_name).ehto_tayttyy, [])
    
    def list_ingredient(self, ingredient: str):
        return self._list_ehto(self._orders, IngredientStrategia(ingredient).ehto_tayttyy, [])
    

    def _mark_ehto(self, id: int, action):
        for order in self._orders:
            if order.id == id:
                action(order)   

    def mark_delivered(self, id: int):
        self._mark_ehto(id, MarkDeliveredStrategia().suorita)

    def mark_making(self, id: int):
        self._mark_ehto(id, MarkMakingStrategia().suorita)

    def take_order(self, order: Order):
        order.id = random.randint(1,10000000)
        self._orders.append(order)

    def export(self, format: str, status: str):
        if format == 'xml':
            strategia = XMLExportStrategia()
        elif format == 'tsv':
            strategia = TSVExportStrategia()
        else:
            raise ValueError(f'unsupported format: {format}')
        
        strategia.tulosta_otsikko()
        
        for order in self._orders:
            if order.status == status:
                strategia.tulosta_tilaus(order)

        strategia.tulosta_lopetus()


def create_order(pizzeria, customer_name, customer_address, ingredients):
    order = Order(customer_name, customer_address, ingredients)
    pizzeria.take_order(order)
    return order
    

def main():
  pizzeria = CopyPizza()

  order = create_order(pizzeria, "Kalle Ilves", "Koskelantie 100", ["kinkku", "jauheliha", "pekoni", "kebab", "salami"])

  pizzeria.mark_making(order.id)
  pizzeria.mark_delivered(order.id)

  order = create_order(pizzeria, "Riikka Korolainen", "Kumpulankaari 55", ["kinkku", "ananas", "aurajuusto"])

  for pizza in pizzeria.list_delivered():
      print(pizza)

  pizzeria.export("xml","delivered")
  pizzeria.save()

main()