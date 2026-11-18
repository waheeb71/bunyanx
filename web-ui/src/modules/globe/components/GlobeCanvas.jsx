import { useEffect, useRef, useCallback } from 'react';
import * as THREE from 'three';
import { useGlobeStore } from '../stores/useGlobeStore';

const DEFAULT_TARGETS = [
  { id: 'taiz-hq', name: 'المقر الرئيسي – تعز 🇾🇪', country: 'اليمن', lat: 13.5795, lon: 44.0206, color: '#00e676', flag: '🇾🇪' }
];

const TEXTURES_LOCAL = {
  day: '/textures/earth-day.jpg',
  normal: '/textures/earth-normal.jpg',
  specular: '/textures/earth-specular.jpg',
  clouds: '/textures/earth-clouds.png',
  night: '/textures/earth-night.jpg',
};

const REGIONS = [
  { name: 'الشرق الأوسط', lat: 25.0, lon: 45.0, color: '#eef6ff', valueColor: '#ff4d6a', glow: 'rgba(255,77,109,0.4)' },
  { name: 'أوروبا', lat: 48.0, lon: 14.0, color: '#eef6ff', valueColor: '#00e676', glow: 'rgba(0,230,118,0.4)' },
  { name: 'أفريقيا', lat: 2.0, lon: 16.0, color: '#eef6ff', valueColor: '#00e676', glow: 'rgba(0,230,118,0.4)' },
  { name: 'أمريكا الشمالية', lat: 40.0, lon: -100.0, color: '#eef6ff', valueColor: '#00d4ff', glow: 'rgba(0,212,255,0.4)' },
  { name: 'أمريكا الجنوبية', lat: -15.0, lon: -58.0, color: '#eef6ff', valueColor: '#00d4ff', glow: 'rgba(0,212,255,0.4)' },
  { name: 'آسيا', lat: 35.0, lon: 100.0, color: '#eef6ff', valueColor: '#00e676', glow: 'rgba(0,230,118,0.4)' },
];

function ll2v3(lat, lon, r = 1.01) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta)
  );
}

const updateRegionSprite = (spriteObj, count) => {
  const { canvas, ctx, texture, name, color, valueColor, glow } = spriteObj;
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  ctx.shadowColor = glow;
  ctx.shadowBlur = 18;

  ctx.font = '800 38px Cairo';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = color;
  ctx.fillText(name, 256, 45);

  ctx.font = '900 46px Cairo';
  ctx.fillStyle = valueColor;
  ctx.fillText((count || 0).toLocaleString('en-US'), 256, 115);

  texture.needsUpdate = true;
};

export function GlobeCanvas({ activeAttacks = [], regionCounts = {}, targets = DEFAULT_TARGETS, onLoaded, onSelectThreat }) {
  const containerRef = useRef(null);
  const mapMode = useGlobeStore((s) => s.mapMode);

  const sceneRef = useRef(null);
  const activeArcsRef = useRef([]);
  const regionSpritesRef = useRef([]);
  const processedArcsRef = useRef(new Set());
  const controlsRef = useRef({ rotX: 0.38, rotY: -0.9, drag: false, prev: { x: 0, y: 0 }, autoRotate: true });

  const targetsRef = useRef(targets);
  const onLoadedRef = useRef(onLoaded);
  const onSelectThreatRef = useRef(onSelectThreat);

  useEffect(() => {
    targetsRef.current = targets;
  }, [targets]);

  useEffect(() => {
    onLoadedRef.current = onLoaded;
  }, [onLoaded]);

  useEffect(() => {
    onSelectThreatRef.current = onSelectThreat;
  }, [onSelectThreat]);

  const impactPulse = useCallback((atk) => {
    const arcGroup = sceneRef.current?.arcGroup;
    if (!arcGroup) return;

    const currentTargets = targetsRef.current || DEFAULT_TARGETS;
    const defaultTarget = currentTargets[0] || DEFAULT_TARGETS[0];
    const tLat = typeof atk?.dstLat === 'number' ? atk.dstLat : typeof defaultTarget.lat === 'number' ? defaultTarget.lat : 13.5795;
    const tLon = typeof atk?.dstLng === 'number' ? atk.dstLng : typeof defaultTarget.lng === 'number' ? defaultTarget.lng : typeof defaultTarget.lon === 'number' ? defaultTarget.lon : 44.0206;

    const targetPos = ll2v3(tLat, tLon, 1.03);
    const color = new THREE.Color(atk?.blocked ? '#00e676' : atk?.color || atk?.col || '#ff4d6d');
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(0.01, 0.035, 32),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide, blending: THREE.AdditiveBlending })
    );
    ring.position.copy(targetPos);
    ring.lookAt(targetPos.clone().multiplyScalar(2));
    arcGroup.add(ring);

    let t = 0;
    const animateRing = () => {
      t += 0.03;
      ring.scale.setScalar(1 + t * 6);
      ring.material.opacity = Math.max(0, 0.9 - t);
      if (t < 1) {
        requestAnimationFrame(animateRing);
      } else {
        arcGroup.remove(ring);
        ring.geometry?.dispose();
        ring.material?.dispose();
      }
    };
    animateRing();
  }, []);

  const createArc = useCallback((atk) => {
    const arcGroup = sceneRef.current?.arcGroup;
    if (!arcGroup || !atk) return;

    const currentTargets = targetsRef.current || DEFAULT_TARGETS;
    const defaultTarget = currentTargets[0] || DEFAULT_TARGETS[0];

    // Source (المصدر / مكان انطلاق الهجوم)
    const srcLat = typeof atk.srcLat === 'number' ? atk.srcLat : typeof atk.startLat === 'number' ? atk.startLat : typeof atk.lat === 'number' ? atk.lat : 35.8617;
    const srcLon = typeof atk.srcLng === 'number' ? atk.srcLng : typeof atk.startLng === 'number' ? atk.startLng : typeof atk.srcLon === 'number' ? atk.srcLon : typeof atk.lon === 'number' ? atk.lon : 104.1954;

    // Destination / Target (الهدف / المقر المستهدف)
    const dstLat = typeof atk.dstLat === 'number' ? atk.dstLat : typeof atk.endLat === 'number' ? atk.endLat : typeof defaultTarget.lat === 'number' ? defaultTarget.lat : 13.5795;
    const dstLon = typeof atk.dstLng === 'number' ? atk.dstLng : typeof atk.endLng === 'number' ? atk.endLng : typeof defaultTarget.lng === 'number' ? defaultTarget.lng : typeof defaultTarget.lon === 'number' ? defaultTarget.lon : 44.0206;

    // Build trajectory from Source (Start) to Destination (End)
    const start = ll2v3(srcLat, srcLon, 1.012);
    const end = ll2v3(dstLat, dstLon, 1.02);
    const distance = start.distanceTo(end);
    const mid = start.clone().add(end).normalize().multiplyScalar(1.18 + Math.min(0.5, distance * 0.24));
    const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
    const points = curve.getPoints(80);
    const color = new THREE.Color(atk.col || atk.color || '#ff4d6d');

    // Trail line
    const line = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints(points.slice(0, 2)),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending })
    );

    // Projectile Head (moves towards destination)
    const head = new THREE.Mesh(
      new THREE.SphereGeometry(0.013, 14, 14),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 })
    );

    // Projectile Tail glow
    const tail = new THREE.Mesh(
      new THREE.SphereGeometry(0.022, 10, 10),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.25 })
    );

    // Attack Origin marker (pulsing circle at source)
    const origin = new THREE.Mesh(
      new THREE.RingGeometry(0.012, 0.024, 24),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.45, side: THREE.DoubleSide, blending: THREE.AdditiveBlending })
    );
    origin.position.copy(start);
    origin.lookAt(start.clone().multiplyScalar(2));

    arcGroup.add(line, head, tail, origin);

    activeArcsRef.current.push({
      atk, curve, points, line, head, tail, origin,
      p: 0,
      duration: 1.8 + Math.random() * 1.4,
    });
  }, []);

  // Sync active attack arcs
  useEffect(() => {
    if (!activeAttacks || activeAttacks.length === 0) return;
    activeAttacks.forEach((atk) => {
      const atkId = atk.id || `${atk.ip}-${atk.time}`;
      if (!processedArcsRef.current.has(atkId)) {
        processedArcsRef.current.add(atkId);
        createArc(atk);
      }
    });

    if (processedArcsRef.current.size > 200) {
      const arr = [...processedArcsRef.current];
      processedArcsRef.current = new Set(arr.slice(-100));
    }
  }, [activeAttacks, createArc]);

  // Update region 3D sprites when counts update
  useEffect(() => {
    if (regionSpritesRef.current && regionSpritesRef.current.length > 0) {
      regionSpritesRef.current.forEach((spriteObj) => {
        const count = regionCounts[spriteObj.name] || 0;
        updateRegionSprite(spriteObj, count);
      });
    }
  }, [regionCounts]);

  // Update target infrastructure markers dynamically
  useEffect(() => {
    const s = sceneRef.current;
    if (!s || !s.targetGroup) return;

    // Rebuild target markers inside targetGroup
    // Clear old target pins (preserve region sprites)
    const targetPins = s.targetGroup.children.filter((c) => c.isGroup);
    targetPins.forEach((grp) => {
      s.targetGroup.remove(grp);
      grp.traverse((child) => {
        child.geometry?.dispose();
        child.material?.dispose();
      });
    });

    (targets || DEFAULT_TARGETS).forEach((target) => {
      const tLat = typeof target.lat === 'number' ? target.lat : 13.5795;
      const tLon = typeof target.lng === 'number' ? target.lng : typeof target.lon === 'number' ? target.lon : 44.0206;
      const p = ll2v3(tLat, tLon, 1.025);
      const grp = new THREE.Group();
      grp.position.copy(p);
      grp.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), p.clone().normalize());
      const core = new THREE.Mesh(new THREE.SphereGeometry(0.01, 12, 12), new THREE.MeshBasicMaterial({ color: target.color || '#00e676' }));
      const ring1 = new THREE.Mesh(new THREE.RingGeometry(0.015, 0.024, 24), new THREE.MeshBasicMaterial({ color: target.color || '#00e676', transparent: true, opacity: 0.6, side: THREE.DoubleSide, blending: THREE.AdditiveBlending }));
      grp.add(core, ring1);
      s.targetGroup.add(grp);
    });
  }, [targets]);

  // Map mode camera position controls
  useEffect(() => {
    const s = sceneRef.current;
    if (!s || !s.camera) return;

    if (mapMode === 'global') {
      s.camera.position.set(0, 0.1, 3.15);
      controlsRef.current.autoRotate = true;
    } else if (mapMode === 'regional') {
      s.camera.position.set(0, 0.3, 2.5);
      controlsRef.current.autoRotate = false;
      controlsRef.current.rotX = 0.35;
      controlsRef.current.rotY = -0.8;
    } else if (mapMode === 'country') {
      s.camera.position.set(-0.2, 0.4, 2.0);
      controlsRef.current.autoRotate = false;
      controlsRef.current.rotX = 0.3;
      controlsRef.current.rotY = -0.9;
    }
  }, [mapMode]);

  // ThreeJS Scene Setup (Only runs once on mount)
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;

    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 1000);
    camera.position.set(0, 0.1, 3.15);

    const arcGroup = new THREE.Group();
    const targetGroup = new THREE.Group();
    scene.add(arcGroup, targetGroup);

    scene.add(new THREE.AmbientLight(0x203040, 1.4));
    scene.add(new THREE.HemisphereLight(0x7fc7ff, 0x081018, 0.7));
    const sunLight = new THREE.DirectionalLight(0xffffff, 2.4);
    sunLight.position.set(4, 2, 4);
    scene.add(sunLight);

    const loadTexture = (key) =>
      new Promise((resolve) => {
        new THREE.TextureLoader().load(
          TEXTURES_LOCAL[key],
          (t) => resolve(t),
          undefined,
          () => resolve(null)
        );
      });

    let isMounted = true;

    Promise.all([
      loadTexture('day'),
      loadTexture('normal'),
      loadTexture('specular'),
      loadTexture('clouds'),
      loadTexture('night'),
    ]).then(([day, normal, specular, cloudsTex, night]) => {
      if (!isMounted) return;

      const globeMat = new THREE.MeshStandardMaterial({
        map: day || null,
        normalMap: normal || null,
        roughness: 0.9,
        metalness: 0.05,
        emissive: new THREE.Color(0x1a3366),
        emissiveMap: night || null,
        emissiveIntensity: 0.55,
        color: day ? 0xffffff : 0x142848,
      });

      const globe = new THREE.Mesh(new THREE.SphereGeometry(1, 96, 96), globeMat);
      globe.rotation.y = Math.PI;
      scene.add(globe);

      if (day && specular) {
        const specOverlay = new THREE.Mesh(
          new THREE.SphereGeometry(1.001, 96, 96),
          new THREE.MeshPhongMaterial({ map: day, specularMap: specular, transparent: true, opacity: 0.25, shininess: 24 })
        );
        specOverlay.rotation.y = Math.PI;
        scene.add(specOverlay);
      }

      const clouds = new THREE.Mesh(
        new THREE.SphereGeometry(1.018, 72, 72),
        new THREE.MeshPhongMaterial({ map: cloudsTex || null, color: 0xffffff, transparent: true, opacity: cloudsTex ? 0.28 : 0.08, depthWrite: false })
      );
      clouds.rotation.y = Math.PI;
      scene.add(clouds);

      const atmoMat = new THREE.ShaderMaterial({
        vertexShader: 'varying vec3 vNormal;void main(){vNormal=normalize(normalMatrix*normal);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}',
        fragmentShader: 'varying vec3 vNormal;void main(){float fresnel=pow(0.78-dot(vNormal,vec3(0.,0.,1.)),3.2);gl_FragColor=vec4(0.14,0.58,1.0,fresnel*0.45);}',
        transparent: true,
        blending: THREE.AdditiveBlending,
        side: THREE.BackSide,
      });
      scene.add(new THREE.Mesh(new THREE.SphereGeometry(1.065, 64, 64), atmoMat));

      // Starfield background
      const starGeo = new THREE.BufferGeometry();
      const count = 2500;
      const starPos = new Float32Array(count * 3);
      for (let i = 0; i < count; i++) {
        const r = 9 + Math.random() * 6;
        const u = Math.random() * 2 - 1;
        const a = Math.random() * Math.PI * 2;
        const s = Math.sqrt(1 - u * u);
        starPos[i * 3] = r * s * Math.cos(a);
        starPos[i * 3 + 1] = r * u;
        starPos[i * 3 + 2] = r * s * Math.sin(a);
      }
      starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
      scene.add(new THREE.Points(starGeo, new THREE.PointsMaterial({ size: 0.015, color: 0x8ab4f8, transparent: true, opacity: 0.85 })));

      // Infrastructure targets
      const currentTargets = targetsRef.current || DEFAULT_TARGETS;
      currentTargets.forEach((target) => {
        const tLat = typeof target.lat === 'number' ? target.lat : 13.5795;
        const tLon = typeof target.lng === 'number' ? target.lng : typeof target.lon === 'number' ? target.lon : 44.0206;
        const p = ll2v3(tLat, tLon, 1.025);
        const grp = new THREE.Group();
        grp.position.copy(p);
        grp.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), p.clone().normalize());
        const core = new THREE.Mesh(new THREE.SphereGeometry(0.01, 12, 12), new THREE.MeshBasicMaterial({ color: target.color || '#00e676' }));
        const ring1 = new THREE.Mesh(new THREE.RingGeometry(0.015, 0.022, 24), new THREE.MeshBasicMaterial({ color: target.color || '#00e676', transparent: true, opacity: 0.6, side: THREE.DoubleSide, blending: THREE.AdditiveBlending }));
        grp.add(core, ring1);
        targetGroup.add(grp);
      });

      // Region 3D sprites
      const regionSprites = [];
      REGIONS.forEach((reg) => {
        const p = ll2v3(reg.lat, reg.lon, 1.055);
        const canvas = document.createElement('canvas');
        canvas.width = 512;
        canvas.height = 160;
        const ctx = canvas.getContext('2d');
        const texture = new THREE.CanvasTexture(canvas);
        const mat = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(0.38, 0.12, 1);
        sprite.position.copy(p);

        const spriteObj = {
          canvas, ctx, texture, sprite,
          name: reg.name,
          color: reg.color,
          valueColor: reg.valueColor,
          glow: reg.glow,
        };

        updateRegionSprite(spriteObj, regionCounts[reg.name] || 0);
        targetGroup.add(sprite);
        regionSprites.push(spriteObj);
      });

      regionSpritesRef.current = regionSprites;
      sceneRef.current = { renderer, scene, camera, globe, clouds, arcGroup, targetGroup, sunLight };

      if (onLoadedRef.current) onLoadedRef.current();
    });

    const dom = renderer.domElement;
    const handleMouseDown = (e) => {
      controlsRef.current.drag = true;
      controlsRef.current.autoRotate = false;
      controlsRef.current.prev = { x: e.clientX, y: e.clientY };
    };
    const handleMouseUp = () => { controlsRef.current.drag = false; };
    const handleMouseMove = (e) => {
      if (!controlsRef.current.drag) return;
      controlsRef.current.rotY += (e.clientX - controlsRef.current.prev.x) * 0.0035;
      controlsRef.current.rotX += (e.clientY - controlsRef.current.prev.y) * 0.0035;
      controlsRef.current.rotX = Math.max(-1.1, Math.min(1.1, controlsRef.current.rotX));
      controlsRef.current.prev = { x: e.clientX, y: e.clientY };
    };
    const handleWheel = (e) => {
      e.preventDefault();
      camera.position.z = Math.max(1.8, Math.min(4.5, camera.position.z + e.deltaY * 0.0018));
    };

    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleCanvasClick = (e) => {
      if (!sceneRef.current || !onSelectThreatRef.current) return;
      const rect = dom.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const clickables = [];
      activeArcsRef.current.forEach(a => {
        if (a.line) clickables.push(a.line);
        if (a.head) clickables.push(a.head);
        if (a.tail) clickables.push(a.tail);
        if (a.origin) clickables.push(a.origin);
      });

      const intersects = raycaster.intersectObjects(clickables, true);
      if (intersects.length > 0) {
        const hitObj = intersects[0].object;
        const foundArc = activeArcsRef.current.find(a => a.line === hitObj || a.head === hitObj || a.tail === hitObj || a.origin === hitObj);
        if (foundArc && foundArc.atk) {
          onSelectThreatRef.current(foundArc.atk.raw || foundArc.atk);
        }
      }
    };

    dom.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mouseup', handleMouseUp);
    dom.addEventListener('mousemove', handleMouseMove);
    dom.addEventListener('wheel', handleWheel, { passive: false });
    dom.addEventListener('click', handleCanvasClick);

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth || window.innerWidth;
      const h = container.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    const clock = new THREE.Clock();
    let animId;

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const s = sceneRef.current;
      if (!s || !s.globe) return;

      const dt = Math.min(clock.getDelta(), 0.035);
      const t = performance.now() * 0.001;

      if (controlsRef.current.autoRotate) {
        controlsRef.current.rotY += 0.0006;
      }

      s.globe.rotation.x = s.clouds.rotation.x = controlsRef.current.rotX;
      s.globe.rotation.y = s.clouds.rotation.y = controlsRef.current.rotY;
      s.clouds.rotation.y += 0.00025;

      s.targetGroup.rotation.set(controlsRef.current.rotX, controlsRef.current.rotY, 0);
      s.arcGroup.rotation.set(controlsRef.current.rotX, controlsRef.current.rotY, 0);

      s.sunLight.position.set(Math.sin(t * 0.1) * 4, 1.8, Math.cos(t * 0.1) * 4);

      for (let i = activeArcsRef.current.length - 1; i >= 0; i--) {
        const a = activeArcsRef.current[i];
        if (!a || !a.points || !a.curve || !a.line || !a.head || !a.tail) {
          activeArcsRef.current.splice(i, 1);
          continue;
        }
        a.p += dt / (a.duration || 2.0);
        if (a.p >= 1) {
          try {
            impactPulse(a.atk);
            if (s.arcGroup) s.arcGroup.remove(a.line, a.head, a.tail, a.origin);
            [a.line, a.head, a.tail, a.origin].forEach((m) => {
              m?.geometry?.dispose();
              m?.material?.dispose();
            });
          } catch (e) {
            // safe ignore
          }
          activeArcsRef.current.splice(i, 1);
          continue;
        }
        const visiblePts = a.points.slice(0, Math.max(2, Math.floor(a.p * a.points.length)));
        if (visiblePts && visiblePts.length >= 2 && a.line) {
          a.line.geometry?.dispose();
          a.line.geometry = new THREE.BufferGeometry().setFromPoints(visiblePts);
        }
        const p = a.curve.getPoint(Math.min(1, Math.max(0, a.p)));
        const tp = a.curve.getPoint(Math.max(0, a.p - 0.04));
        if (p && a.head) a.head.position.copy(p);
        if (tp && a.tail) a.tail.position.copy(tp);
      }

      renderer.render(s.scene, camera);
    };

    animate();

    return () => {
      isMounted = false;
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mouseup', handleMouseUp);
      dom.removeEventListener('mousedown', handleMouseDown);
      dom.removeEventListener('mousemove', handleMouseMove);
      dom.removeEventListener('wheel', handleWheel);
      dom.removeEventListener('click', handleCanvasClick);
      renderer.dispose();
    };
  }, [impactPulse]);

  return (
    <div ref={containerRef} className="gtm-canvas" />
  );
}

export default GlobeCanvas;
