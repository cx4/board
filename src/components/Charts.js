import * as G2Plot from '@antv/g2plot'
const container = document.getElementById('app');
const data = [
  {
    "x": "家具家电",
    "y": 162
  },
  {
    "x": "粮油副食",
    "y": 348
  },
  {
    "x": "美容洗护",
    "y": 646
  },
  {
    "x": "母婴用品",
    "y": 105
  },
  {
    "x": "进口食品",
    "y": 669
  }
];
const config = {
  "title": {
    "visible": true,
    "text": "饼图"
  },
  "description": {
    "visible": true,
    "text": "一个简单的饼图"
  },
  "legend": {
    "flipPage": false
  },
  "width": 560,
  "height": 376,
  "forceFit": false,
  "radius": 1,
  "colorField": "x",
  "angleField": "y",
  "color": [
    "#5B8FF9",
    "#5AD8A6",
    "#5D7092",
    "#F6BD16",
    "#E8684A"
  ]
}
const plot = new G2Plot.Pie(container, {
  data,
  ...config,
});
plot.render();