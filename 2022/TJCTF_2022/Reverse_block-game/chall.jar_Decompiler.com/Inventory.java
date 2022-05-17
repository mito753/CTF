import java.awt.Color;
import java.awt.Graphics;
import java.util.ArrayList;

public class Inventory {
   private final int height = 50;
   private final int width;
   private final Game game;
   private final Inventory.InventoryItem[] items;
   private int selectedItem = 0;
   private final Color backgroundColor = new Color(255, 255, 255, 70);

   public Inventory(Game var1) {
      this.game = var1;
      ArrayList var2 = new ArrayList();

      for(int var3 = 0; var3 < Tile.TileType.values().length; ++var3) {
         if (Tile.TileType.values()[var3].showInInventory) {
            var2.add(new Inventory.InventoryItem(Tile.TileType.values()[var3]));
         }
      }

      this.items = (Inventory.InventoryItem[])var2.toArray(new Inventory.InventoryItem[0]);
      this.width = this.items.length * 40 + 10;
   }

   public void tick() {
   }

   public void render(Graphics var1) {
      var1.setColor(this.backgroundColor);
      var1.fillRect(this.game.getWidth() / 2 - this.width / 2, this.game.getHeight() - 100, this.width, 50);
      int var2 = 0;
      Inventory.InventoryItem[] var3 = this.items;
      int var4 = var3.length;

      for(int var5 = 0; var5 < var4; ++var5) {
         Inventory.InventoryItem var6 = var3[var5];
         if (this.selectedItem == var2) {
            var1.setColor(this.backgroundColor);
            var1.fillRect(this.game.getWidth() / 2 - this.width / 2 + 40 * var2 + 5, this.game.getHeight() - 100 + 5, 40, 40);
         }

         var1.setColor(var6.type.color);
         var1.fillRect(this.game.getWidth() / 2 - this.width / 2 + 40 * var2 + 10, this.game.getHeight() - 100 + 10, 30, 30);
         ++var2;
      }

   }

   public Inventory.InventoryItem getSelectedItem() {
      return this.items[this.selectedItem];
   }

   public void setSelectedItem(int var1) {
      while(var1 < 0) {
         var1 += this.items.length;
      }

      this.selectedItem = var1 % this.items.length;
   }

   class InventoryItem {
      private final Tile.TileType type;

      public InventoryItem(Tile.TileType var2) {
         this.type = var2;
      }

      public Tile.TileType getType() {
         return this.type;
      }
   }
}
