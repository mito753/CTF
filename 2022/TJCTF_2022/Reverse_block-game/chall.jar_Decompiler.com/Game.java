import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferStrategy;
import java.nio.ByteBuffer;
import javax.swing.JFrame;

public class Game extends JFrame implements Runnable {
   private boolean running = false;
   public static final int FPS = 60;
   private static final double deltaBetweenFrames = 1.6666666666666666E7D;
   public static final int TILE_SIZE = 20;
   public static final int MAX_Z = 8;
   private final Tile[][][] tiles;
   private final Player player;
   private final Inventory inventory;
   private final int mapWidth;
   private final int mapHeight;
   public static final Color BACKGROUND_COLOR = new Color(10087167);

   public Game(int var1, int var2) {
      this.mapWidth = var1;
      this.mapHeight = var2;
      this.tiles = new Tile[var2][var1][8];

      for(int var3 = 0; var3 < this.tiles.length; ++var3) {
         for(int var4 = 0; var4 < this.tiles[var3].length; ++var4) {
            for(int var5 = 0; var5 < this.tiles[var3][var4].length; ++var5) {
               if (var5 == 7) {
                  this.tiles[var3][var4][var5] = new Tile(Tile.TileType.GRASS, var4, var3, var5);
                  if (Math.random() < 0.04D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.WATER);
                  } else if (Math.random() < 0.2D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.SAND);
                  }
               } else if (var5 >= 4) {
                  this.tiles[var3][var4][var5] = new Tile(Tile.TileType.DIRT, var4, var3, var5);
                  if (Math.random() > (double)var5 / 10.0D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.STONE);
                  }
               } else {
                  this.tiles[var3][var4][var5] = new Tile(Tile.TileType.STONE, var4, var3, var5);
                  if (Math.random() < 0.2D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.GRANITE);
                  } else if (Math.random() < 0.008D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.LAVA);
                  } else if (Math.random() < 0.005D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.IRON);
                  } else if (Math.random() < 0.004D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.LAPIS);
                  } else if (Math.random() < 0.003D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.GOLD);
                  } else if (Math.random() < 0.002D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.DIAMOND);
                  } else if (Math.random() < 0.001D) {
                     this.tiles[var3][var4][var5].setType(Tile.TileType.EMERALD);
                  }
               }

               if (Math.random() < 1.0E-4D) {
                  this.tiles[var3][var4][var5].setType(Tile.TileType.STAIRS_DOWN);
               } else if (Math.random() < 1.0E-4D) {
                  this.tiles[var3][var4][var5].setType(Tile.TileType.STAIRS_UP);
               }
            }
         }
      }

      this.inventory = new Inventory(this);
      this.player = new Player(this, this.inventory, this.tiles[0].length / 2, this.tiles.length / 2, 0);
   }

   public void saveData() {
      int var1 = 0;
      byte[] var2 = new byte[17 + this.tiles.length * this.tiles[0].length * 4];
      byte[] var3 = ByteBuffer.allocate(4).putInt((int)this.player.getX()).array();
      int var4 = var3.length;

      int var5;
      byte var6;
      for(var5 = 0; var5 < var4; ++var5) {
         var6 = var3[var5];
         System.out.println(var6);
         var2[var1++] = var6;
      }

      var3 = ByteBuffer.allocate(4).putInt((int)this.player.getY()).array();
      var4 = var3.length;

      for(var5 = 0; var5 < var4; ++var5) {
         var6 = var3[var5];
         var2[var1++] = var6;
      }

      var2[var1++] = (byte)this.player.getZ();
      var3 = ByteBuffer.allocate(4).putInt(this.mapWidth).array();
      var4 = var3.length;

      for(var5 = 0; var5 < var4; ++var5) {
         var6 = var3[var5];
         var2[var1++] = var6;
      }

      var3 = ByteBuffer.allocate(4).putInt(this.mapHeight).array();
      var4 = var3.length;

      for(var5 = 0; var5 < var4; ++var5) {
         var6 = var3[var5];
         var2[var1++] = var6;
      }

      for(int var8 = 0; var8 < this.tiles.length; ++var8) {
         for(var4 = 0; var4 < this.tiles[var8].length; ++var4) {
            for(var5 = 0; var5 < 8; var5 += 2) {
               var6 = 0;

               for(int var7 = 0; var7 < 2; ++var7) {
                  var6 |= (byte)(this.tiles[var8][var4][var7 + var5].getType().id << var7 * 4);
               }

               var2[var1++] = var6;
            }
         }
      }

      FileManager.saveData(var2);
   }

   public Tile getTileAt(int var1, int var2, int var3) {
      return var1 >= 0 && var2 >= 0 && var3 >= 0 && var2 < this.tiles.length && var1 < this.tiles[0].length && var3 < this.tiles[0][0].length ? this.tiles[var2][var1][var3] : null;
   }

   public void tick() {
      this.player.tick();
   }

   public void render() {
      BufferStrategy var1 = this.getBufferStrategy();
      if (var1 == null) {
         this.createBufferStrategy(3);
      } else {
         Graphics2D var2 = (Graphics2D)var1.getDrawGraphics();
         var2.setColor(BACKGROUND_COLOR);
         var2.fillRect(0, 0, this.getWidth(), this.getHeight());
         double var3 = this.player.getX() * 20.0D - (double)(this.getWidth() / 2);
         double var5 = this.player.getY() * 20.0D - (double)(this.getHeight() / 2);

         for(int var7 = Math.max(0, (int)this.player.getY() - this.getHeight() / 20); (double)var7 < Math.min((double)this.tiles.length, this.player.getY() + (double)(this.getHeight() / 20)); ++var7) {
            for(int var8 = Math.max(0, (int)this.player.getX() - this.getWidth() / 20); (double)var8 < Math.min((double)this.tiles[0].length, this.player.getX() + (double)(this.getWidth() / 20)); ++var8) {
               Tile var9 = this.tiles[var7][var8][this.player.getZ()];
               var9.render(var2, var3, var5);
            }
         }

         this.player.render(var2, this.getWidth() / 2, this.getHeight() / 2);
         this.inventory.render(var2);
         var2.dispose();
         var1.show();
      }
   }

   public int getMapWidth() {
      return this.mapWidth;
   }

   public int getMapHeight() {
      return this.mapHeight;
   }

   public Player getPlayer() {
      return this.player;
   }

   public synchronized void start() {
      if (!this.running) {
         this.running = true;
         (new Thread(this)).start();
      }
   }

   public synchronized void stop() {
      if (this.running) {
         try {
            Thread.currentThread().join();
            this.running = false;
         } catch (InterruptedException var2) {
            var2.printStackTrace();
         }

      }
   }

   public void run() {
      int var1 = 0;
      double var2 = (double)System.nanoTime();
      double var4 = (double)System.currentTimeMillis();

      while(this.running) {
         double var6 = (double)System.nanoTime();
         if (var6 - var2 >= 1.6666666666666666E7D) {
            this.tick();
            this.render();
            var2 = var6;
            ++var1;
         }

         double var8 = (double)System.currentTimeMillis();
         if (var8 - var4 >= 1000.0D) {
            System.out.println("FPS: " + var1);
            var1 = 0;
            var4 = var8;
         }
      }

   }
}
