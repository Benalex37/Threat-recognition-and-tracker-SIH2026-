/* Offline world map renderer.
 *
 * Draws an equirectangular threat map on a canvas with no tile server, no
 * Leaflet and no network access of any kind. The basemap is the dot grid built
 * by scripts/build_world_grid.py from the local IP database; markers, campaign
 * arcs and pulses are drawn on top.
 *
 *   const map = new WorldMap(canvas, { onHover, onSelect });
 *   await map.loadGrid("/static/world_grid.json");
 *   map.setMarkers([...]); map.setLinks([...]);
 */
(function (global) {
  "use strict";

  // Clipping the poles removes mostly-empty space and fills the frame better.
  const LAT_TOP = 79;
  const LAT_BOTTOM = -57;
  const MIN_ZOOM = 1;
  const MAX_ZOOM = 9;

  // Tuned for the light basemap: ink-on-paper rather than glow-on-black.
  const COLORS = {
    dot: [13, 91, 196],
    graticule: "rgba(6, 32, 63, .22)",
    link: "#6f42c1",
    selected: "#06203f",
    hover: "#0d5bc4",
    markerEdge: "rgba(6, 32, 63, .38)",
  };

  function clamp(value, min, max) {
    return value < min ? min : value > max ? max : value;
  }

  class WorldMap {
    constructor(canvas, options) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.options = options || {};
      this.cells = [];          // [{x, y, level}] in normalised 0..1 space
      this.markers = [];
      this.links = [];
      this.selectedId = null;
      this.hoverId = null;
      this.zoom = 1;
      this.offsetX = 0;
      this.offsetY = 0;
      this.width = 0;
      this.height = 0;
      this.dpr = Math.min(global.devicePixelRatio || 1, 2);
      this._frame = null;
      this._start = performance.now();
      this._hit = [];

      this._bindEvents();
      this._observeSize();
    }

    /* ------------------------------------------------------------ basemap */
    async loadGrid(url) {
      try {
        const response = await fetch(url, { cache: "force-cache" });
        if (!response.ok) throw new Error("HTTP " + response.status);
        this._decodeGrid(await response.json());
      } catch (err) {
        // A missing asset must not take the map down — markers still render.
        console.warn("World grid unavailable, drawing markers only:", err.message);
        this.cells = [];
      }
      this.draw();
    }

    _decodeGrid(payload) {
      const binary = atob(payload.data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

      const { cols, rows, lat_step: latStep, lon_step: lonStep } = payload;
      const cells = [];
      for (let index = 0; index < cols * rows; index++) {
        const level = (bytes[index >> 2] >> ((index & 3) * 2)) & 3;
        if (!level) continue;
        const row = Math.floor(index / cols);
        const col = index % cols;
        const lat = 90 - row * latStep - latStep / 2;
        const lon = -180 + col * lonStep + lonStep / 2;
        if (lat > LAT_TOP || lat < LAT_BOTTOM) continue;
        cells.push({
          nx: (lon + 180) / 360,
          ny: (LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM),
          level,
        });
      }
      this.cells = cells;
      this.cellStep = lonStep;
    }

    /* ------------------------------------------------------------- layout */
    _observeSize() {
      const resize = () => {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = Math.max(rect.width, 10);
        this.height = Math.max(rect.height, 10);
        this.canvas.width = Math.round(this.width * this.dpr);
        this.canvas.height = Math.round(this.height * this.dpr);
        this.canvas.style.width = this.width + "px";
        this.canvas.style.height = this.height + "px";
        this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
        this.draw();
      };
      if (global.ResizeObserver) {
        new ResizeObserver(resize).observe(this.canvas.parentElement);
      } else {
        global.addEventListener("resize", resize);
      }
      resize();
    }

    /* ------------------------------------------------------------- inputs */
    _bindEvents() {
      const canvas = this.canvas;
      let dragging = false;
      let lastX = 0;
      let lastY = 0;
      let moved = 0;

      canvas.addEventListener("pointerdown", (event) => {
        dragging = true;
        moved = 0;
        lastX = event.clientX;
        lastY = event.clientY;
        canvas.setPointerCapture(event.pointerId);
        canvas.parentElement.classList.add("is-panning");
      });

      canvas.addEventListener("pointermove", (event) => {
        if (dragging) {
          const dx = event.clientX - lastX;
          const dy = event.clientY - lastY;
          moved += Math.abs(dx) + Math.abs(dy);
          this.offsetX += dx;
          this.offsetY += dy;
          lastX = event.clientX;
          lastY = event.clientY;
          this._clampOffset();
          this.draw();
          return;
        }
        this._handleHover(event);
      });

      const endDrag = (event) => {
        if (!dragging) return;
        dragging = false;
        canvas.parentElement.classList.remove("is-panning");
        if (moved < 4) this._handleClick(event);
      };
      canvas.addEventListener("pointerup", endDrag);
      canvas.addEventListener("pointercancel", () => { dragging = false; });
      canvas.addEventListener("pointerleave", () => {
        this.hoverId = null;
        if (this.options.onHover) this.options.onHover(null);
        this.draw();
      });

      canvas.addEventListener("wheel", (event) => {
        event.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const px = event.clientX - rect.left;
        const py = event.clientY - rect.top;
        const factor = event.deltaY < 0 ? 1.22 : 1 / 1.22;
        this.zoomAt(px, py, factor);
      }, { passive: false });
    }

    zoomAt(px, py, factor) {
      const next = clamp(this.zoom * factor, MIN_ZOOM, MAX_ZOOM);
      const applied = next / this.zoom;
      // Keep the point under the cursor fixed while scaling.
      this.offsetX = px - (px - this.offsetX) * applied;
      this.offsetY = py - (py - this.offsetY) * applied;
      this.zoom = next;
      this._clampOffset();
      this.draw();
    }

    _clampOffset() {
      const scaledW = this.width * this.zoom;
      const scaledH = this.height * this.zoom;
      const minX = Math.min(0, this.width - scaledW);
      const minY = Math.min(0, this.height - scaledH);
      this.offsetX = clamp(this.offsetX, minX, 0);
      this.offsetY = clamp(this.offsetY, minY, 0);
    }

    resetView() {
      this.zoom = 1;
      this.offsetX = 0;
      this.offsetY = 0;
      this.draw();
    }

    _pointFor(nx, ny) {
      return {
        x: nx * this.width * this.zoom + this.offsetX,
        y: ny * this.height * this.zoom + this.offsetY,
      };
    }

    _markerPoint(marker) {
      const nx = (marker.lon + 180) / 360;
      const ny = (LAT_TOP - marker.lat) / (LAT_TOP - LAT_BOTTOM);
      return this._pointFor(nx, clamp(ny, 0, 1));
    }

    _handleHover(event) {
      const rect = this.canvas.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const hit = this._hitTest(x, y);
      const id = hit ? hit.marker.id : null;
      if (id !== this.hoverId) {
        this.hoverId = id;
        this.draw();
      }
      if (this.options.onHover) {
        this.options.onHover(hit ? { marker: hit.marker, x: hit.x, y: hit.y } : null);
      }
    }

    _handleClick(event) {
      const rect = this.canvas.getBoundingClientRect();
      const hit = this._hitTest(event.clientX - rect.left, event.clientY - rect.top);
      if (this.options.onSelect) this.options.onSelect(hit ? hit.marker : null);
    }

    _hitTest(x, y) {
      let best = null;
      let bestDistance = Infinity;
      for (const entry of this._hit) {
        const dx = x - entry.x;
        const dy = y - entry.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        if (distance <= entry.radius + 7 && distance < bestDistance) {
          bestDistance = distance;
          best = entry;
        }
      }
      return best;
    }

    /* -------------------------------------------------------------- state */
    setMarkers(markers) {
      this.markers = markers || [];
      this.draw();
    }

    setLinks(links) {
      this.links = links || [];
      this.draw();
    }

    setSelected(id) {
      this.selectedId = id;
      this.draw();
    }

    /* ------------------------------------------------------------ drawing */
    draw() {
      if (this._frame) return;
      this._frame = requestAnimationFrame(() => {
        this._frame = null;
        this._render();
      });
    }

    _render() {
      const ctx = this.ctx;
      if (!ctx || !this.width) return;
      ctx.clearRect(0, 0, this.width, this.height);

      this._drawGrid(ctx);
      this._drawGraticule(ctx);
      this._drawLinks(ctx);
      this._drawMarkers(ctx);

      // Keep animating only while something is actually pulsing.
      if (this.markers.some((m) => m.pulse)) this.draw();
    }

    _drawGrid(ctx) {
      if (!this.cells.length) return;
      const size = clamp((this.width / 360) * this.zoom * 1.25, 0.85, 4.5);
      const [r, g, b] = COLORS.dot;
      const alphas = [0, 0.20, 0.40, 0.72];
      let currentLevel = -1;

      for (const cell of this.cells) {
        const point = this._pointFor(cell.nx, cell.ny);
        if (point.x < -4 || point.x > this.width + 4 || point.y < -4 || point.y > this.height + 4) continue;
        if (cell.level !== currentLevel) {
          currentLevel = cell.level;
          ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alphas[currentLevel]})`;
        }
        ctx.fillRect(point.x - size / 2, point.y - size / 2, size, size);
      }
    }

    _drawGraticule(ctx) {
      ctx.strokeStyle = COLORS.graticule;
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 5]);
      ctx.beginPath();
      const equator = this._pointFor(0, (LAT_TOP - 0) / (LAT_TOP - LAT_BOTTOM));
      ctx.moveTo(0, equator.y);
      ctx.lineTo(this.width, equator.y);
      const meridian = this._pointFor(0.5, 0);
      ctx.moveTo(meridian.x, 0);
      ctx.lineTo(meridian.x, this.height);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    _drawLinks(ctx) {
      if (!this.links.length) return;
      const byId = new Map(this.markers.map((m) => [m.id, m]));
      const phase = (performance.now() - this._start) / 34;

      ctx.lineWidth = 1.4;
      ctx.strokeStyle = COLORS.link;
      ctx.globalAlpha = 0.55;
      ctx.setLineDash([4, 4]);
      ctx.lineDashOffset = -phase % 8;

      for (const link of this.links) {
        const from = byId.get(link.from);
        const to = byId.get(link.to);
        if (!from || !to) continue;
        const a = this._markerPoint(from);
        const b = this._markerPoint(to);
        const midX = (a.x + b.x) / 2;
        const midY = (a.y + b.y) / 2;
        const lift = Math.min(Math.hypot(b.x - a.x, b.y - a.y) * 0.32, 130);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(midX, midY - lift, b.x, b.y);
        ctx.stroke();
      }
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
      ctx.lineDashOffset = 0;
    }

    _drawMarkers(ctx) {
      this._hit = [];
      const elapsed = (performance.now() - this._start) / 1000;

      const ordered = this.markers.slice().sort((a, b) => (a.weight || 1) - (b.weight || 1));
      for (const marker of ordered) {
        if (marker.lat == null || marker.lon == null) continue;
        const point = this._markerPoint(marker);
        const radius = marker.radius || 5;
        if (point.x < -40 || point.x > this.width + 40 || point.y < -40 || point.y > this.height + 40) continue;

        this._hit.push({ marker, x: point.x, y: point.y, radius });

        if (marker.pulse) {
          const cycle = (elapsed * 0.62 + (marker.phase || 0)) % 1;
          ctx.beginPath();
          ctx.arc(point.x, point.y, radius + 3 + cycle * 20, 0, Math.PI * 2);
          ctx.strokeStyle = marker.color;
          ctx.globalAlpha = (1 - cycle) * 0.5;
          ctx.lineWidth = 1.6;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }

        // Soft glow behind the marker body. Kept tight and low-alpha so it
        // lifts the marker off the basemap without smudging it.
        const glowRadius = radius * 2.2;
        const glow = ctx.createRadialGradient(point.x, point.y, radius * 0.6, point.x, point.y, glowRadius);
        glow.addColorStop(0, marker.color + "3a");
        glow.addColorStop(1, marker.color + "00");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(point.x, point.y, glowRadius, 0, Math.PI * 2);
        ctx.fill();

        ctx.beginPath();
        ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
        if (marker.approximate) {
          ctx.strokeStyle = marker.color;
          ctx.lineWidth = 2;
          ctx.setLineDash([2.6, 2.4]);
          ctx.stroke();
          ctx.setLineDash([]);
        } else {
          ctx.fillStyle = marker.color;
          ctx.fill();
          ctx.strokeStyle = COLORS.markerEdge;
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }

        if (marker.count > 1) {
          // Outlined white keeps the count readable on every severity fill,
          // including the amber band where plain white would wash out.
          ctx.font = "700 10px " + (getComputedStyle(document.body).fontFamily || "sans-serif");
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.lineWidth = 2.6;
          ctx.strokeStyle = "rgba(6, 32, 63, .9)";
          ctx.strokeText(String(marker.count), point.x, point.y + 0.5);
          ctx.fillStyle = "#ffffff";
          ctx.fillText(String(marker.count), point.x, point.y + 0.5);
        }

        const isActive = marker.id === this.selectedId || marker.id === this.hoverId;
        if (isActive) {
          ctx.strokeStyle = marker.id === this.selectedId ? COLORS.selected : COLORS.hover;
          ctx.lineWidth = 1.8;
          const box = radius + 7;
          ctx.strokeRect(point.x - box, point.y - box, box * 2, box * 2);
        }
      }
    }
  }

  global.WorldMap = WorldMap;
})(window);
