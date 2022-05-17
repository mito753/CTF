import java.awt.Color;
import java.awt.Graphics;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.util.HashMap;
import java.util.Map;

public class Player implements KeyListener, MouseListener, MouseWheelListener {
   Map<Integer, Boolean> keys = new HashMap();
   private Game game;
   private Inventory inventory;
   private double x = 0.0D;
   private double y = 0.0D;
   private int z = 0;
   private boolean onStairs = false;

   public Player(Game var1, Inventory var2, int var3, int var4, int var5) {
      this.game = var1;
      this.x = (double)var3;
      this.y = (double)var4;
      this.z = var5;
      this.inventory = var2;
      var1.addKeyListener(this);
      var1.addMouseListener(this);
      var1.addMouseWheelListener(this);
   }

   public void keyTyped(KeyEvent var1) {
   }

   public void keyPressed(KeyEvent var1) {
      this.keys.put(var1.getKeyCode(), true);
      if (var1.getKeyCode() == 27) {
         System.exit(0);
      } else if (var1.getKeyCode() == 80) {
         this.game.saveData();
      }

   }

   public void keyReleased(KeyEvent var1) {
      this.keys.put(var1.getKeyCode(), false);
   }

   public void tick() {
      if ((Boolean)this.keys.getOrDefault(87, false)) {
         this.y -= 0.1D;
      }

      if ((Boolean)this.keys.getOrDefault(83, false)) {
         this.y += 0.1D;
      }

      if ((Boolean)this.keys.getOrDefault(65, false)) {
         this.x -= 0.1D;
      }

      if ((Boolean)this.keys.getOrDefault(68, false)) {
         this.x += 0.1D;
      }

      this.x = Math.max(0.5D, Math.min(this.x, (double)this.game.getMapWidth() - 0.5D));
      this.y = Math.max(0.5D, Math.min(this.y, (double)this.game.getMapHeight() - 0.5D));
      Tile var1 = this.game.getTileAt((int)this.x, (int)this.y, this.z);
      if (var1.getType() == Tile.TileType.STAIRS_DOWN) {
         if (!this.onStairs && this.z > 0) {
            --this.z;
         }

         this.onStairs = true;
      } else if (var1.getType() == Tile.TileType.STAIRS_UP) {
         if (!this.onStairs && this.z < 7) {
            ++this.z;
         }

         this.onStairs = true;
      } else {
         this.onStairs = false;
      }

   }

   public void build(int var1, int var2) {
      if (this.inActionRange(var1, var2)) {
         Inventory.InventoryItem var3 = this.inventory.getSelectedItem();
         this.game.getTileAt(var1, var2, this.z).setType(var3.getType());
      }

   }

   public void destroy(int var1, int var2) {
      if (this.inActionRange(var1, var2)) {
         this.game.getTileAt(var1, var2, this.z).setType(Tile.TileType.EMPTY);
      }

   }

   public boolean inActionRange(int var1, int var2) {
      return Math.pow((double)var1 - this.x, 2.0D) + Math.pow((double)var2 - this.y, 2.0D) < 25.0D;
   }

   public void render(Graphics var1, int var2, int var3) {
      var1.setColor(Color.RED);
      var1.fillRect(var2 - 10, var3 - 10, 20, 20);
   }

   public double getX() {
      return this.x;
   }

   public double getY() {
      return this.y;
   }

   public int getZ() {
      return this.z;
   }

   public void setX(double var1) {
      this.x = var1;
   }

   public void setY(double var1) {
      this.y = var1;
   }

   public void setZ(int var1) {
      if (var1 >= 0 && var1 <= 8) {
         this.z = var1;
      }
   }

   public void mouseClicked(MouseEvent var1) {
   }

   public void mousePressed(MouseEvent var1) {
      int var2 = (int)(((double)var1.getX() + this.getX() * 20.0D - (double)(this.game.getWidth() / 2)) / 20.0D);
      int var3 = (int)(((double)var1.getY() + this.getY() * 20.0D - (double)(this.game.getHeight() / 2)) / 20.0D);
      if (var1.getButton() == 3) {
         this.build(var2, var3);
      } else if (var1.getButton() == 1) {
         this.destroy(var2, var3);
      }

   }

   public void mouseReleased(MouseEvent var1) {
   }

   public void mouseWheelMoved(MouseWheelEvent var1) {
      this.inventory.setSelectedItem(this.inventory.getSelectedItem().getType().id + var1.getScrollAmount() / var1.getUnitsToScroll());
   }

   public void mouseEntered(MouseEvent var1) {
   }

   public void mouseExited(MouseEvent var1) {
   }
}
