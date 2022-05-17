import java.awt.Color;
import java.awt.Graphics;

public class Tile {
   private int x;
   private int y;
   private int z;
   private Tile.TileType type;

   public Tile(Tile.TileType var1, int var2, int var3, int var4) {
      this.type = var1;
      this.x = var2;
      this.y = var3;
      this.z = var4;
   }

   public int getX() {
      return this.x;
   }

   public int getY() {
      return this.y;
   }

   public int getZ() {
      return this.z;
   }

   public Tile.TileType getType() {
      return this.type;
   }

   public void setType(Tile.TileType var1) {
      this.type = var1;
   }

   public void render(Graphics var1, double var2, double var4) {
      var1.setColor(this.type.color);
      var1.fillRect((int)Math.round((double)(this.x * 20) - var2), (int)Math.round((double)(this.y * 20) - var4), 20, 20);
   }

   public static enum TileType {
      STONE(0, "Stone", new Color(8948877), true),
      GRANITE(1, "Granite", new Color(13467698), true),
      SAND(2, "Sand", new Color(14397818), true),
      DIRT(3, "Dirt", new Color(11762252), true),
      GRASS(4, "Grass", new Color(39447), true),
      WOOD(5, "Wood", new Color(13278311), true),
      IRON(6, "Iron", new Color(13619151), true),
      GOLD(7, "Gold", new Color(16567570), true),
      LAPIS(8, "Lapis", new Color(45823), true),
      DIAMOND(9, "Diamond", new Color(12186367), true),
      EMERALD(10, "Emerald", new Color(3844952), true),
      WATER(11, "Water", new Color(3374266), true),
      LAVA(12, "Lava", new Color(16267788), true),
      STAIRS_DOWN(13, "StairsD", Color.BLACK, true),
      STAIRS_UP(14, "StairsU", Color.WHITE, true),
      EMPTY(15, "Empty", Game.BACKGROUND_COLOR, false);

      public final int id;
      public final String name;
      public final Color color;
      public final boolean showInInventory;

      private TileType(int var3, String var4, Color var5, boolean var6) {
         this.id = var3;
         this.name = var4;
         this.color = var5;
         this.showInInventory = var6;
      }

      // $FF: synthetic method
      private static Tile.TileType[] $values() {
         return new Tile.TileType[]{STONE, GRANITE, SAND, DIRT, GRASS, WOOD, IRON, GOLD, LAPIS, DIAMOND, EMERALD, WATER, LAVA, STAIRS_DOWN, STAIRS_UP, EMPTY};
      }
   }
}
