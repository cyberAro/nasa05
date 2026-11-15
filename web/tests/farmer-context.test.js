import assert from "node:assert/strict";
import test from "node:test";
import { simulateRotation } from "../src/lib/model.js";

const crops = {
  paddy: {
    family: "rice",
    nFix: 0,
    residueC: 1.2,
    cover: 0.8,
    ky: 1.1,
    elasticity: -0.3,
  },
};

const season = {
  water_mm: 100,
  supply: { tank: 1 },
  yield: [1, 2, 3],
  suit: "pass",
  reasons: [],
  price: 50,
  cost: 20,
  planned_area_ha: 900,
  district_area_ha: 1000,
};

const pack = {
  soil: { n_kg_ha: 50, soc_pct: 1.2 },
  slope_pct: 2,
  climate: { seasonRain: { maha: 300, yala: 250 } },
  water: {
    maha: { rain: 100, tank: 100, well: 100 },
    yala: { rain: 100, tank: 100, well: 100 },
  },
  crops: { paddy: { maha: season, yala: season } },
};

const simulate = (options = {}) => simulateRotation(
  pack,
  crops,
  { maha: "paddy", yala: "paddy" },
  { waterSource: "tank", market: true, areaHa: 0, ...options },
);

test("previous crop changes first-season pest pressure and soil nitrogen", () => {
  const baseline = simulate();
  const afterPaddy = simulate({ previousCrop: "paddy" });

  assert.ok(afterPaddy.seasons[0].yield[1] < baseline.seasons[0].yield[1]);
  assert.ok(afterPaddy.traj.n[0] < baseline.traj.n[0]);
});

test("soil texture water estimate changes available seasonal water", () => {
  const baseline = simulate();
  const sandy = simulate({ soilAwcMm: 80, soilTexture: "sandy" });

  assert.ok(sandy.seasons[0].water_mm < baseline.seasons[0].water_mm);
});

test("farm area changes the market estimate", () => {
  const baseline = simulate();
  const oneHectare = simulate({ areaHa: 100 });

  assert.notEqual(oneHectare.seasons[0].priceShift, baseline.seasons[0].priceShift);
});
