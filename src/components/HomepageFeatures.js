import React from 'react';
import clsx from 'clsx';
import styles from './HomepageFeatures.module.css';

const FeatureList = [
  {
    title: '安全测试',
    Svg: require('../../static/img/sercuretest.svg').default,
    description: (
      <>
        在IT软件产品的生命周期中，特别是产品开发基本完成到发布阶段，对产品进行检验以验证产品符合安全需求定义和产品质量标准的过程 。
      </>
    ),
  },
  {
    title: '安全监测',
    Svg: require('../../static/img/monriter.svg').default,
    description: (
      <>
        通过实时分析网上数据流来监测非法入侵活动。
      </>
    ),
  },
  {
    title: '漏洞预警',
    Svg: require('../../static/img/warn.svg').default,
    description: (
      <>
        对在野漏洞和风险中间件进行实时监测，及时对受影响的项目进行预警并提供解决方案。
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} alt={title} />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
