/**
 * Copyright (c) 2017-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* import InnerBgImg from "assets/Passus_strona-06.png"; */
const React = require('react');

const CompLibrary = require('../../core/CompLibrary.js');

const MarkdownBlock = CompLibrary.MarkdownBlock; /* Used to read markdown */
const Container = CompLibrary.Container;
const GridBlock = CompLibrary.GridBlock;


class HomeSplash extends React.Component {
  render() {
    const {siteConfig, language = ''} = this.props;
    const {baseUrl, docsUrl} = siteConfig;
    const docsPart = `${docsUrl ? `${docsUrl}/` : ''}`;
    const langPart = `${language ? `${language}/` : ''}`;
    const docUrl = doc => `${baseUrl}${docsPart}${langPart}${doc}`;

    const SplashContainer = props => (
      <div className="homeContainer">
        <div className="homeSplashFade" >
            <div className="wrapper homeWrapper">{props.children}</div>
        </div>
      </div>
    );
    const Block = props => (
      <Container
        padding={['bottom', 'top']}
        id={props.id}
        background={props.background}>
        <GridBlock
          align="center"
          contents={props.children}
          layout={props.layout}
        />
      </Container>
    );
    const Logo = props => (
      <div className="projectLogo">
        <img src={props.img_src} alt="Project Logo" />
      </div>
    );


    const ProjectTitle = () => (
      <h2 className="projectTitle">
        <small>{siteConfig.tagline}</small>
      </h2>
    );

    const PromoSection = props => (
      <div className="section promoSection">
        <div className="promoRow">
          <div className="pluginRowBlock">{props.children}</div>
        </div>
      </div>
    );

    const Button = props => (
      <div className="pluginWrapper buttonWrapper">
        <a className="button" href={props.href} target={props.target}>
          {props.children}
        </a>
      </div>
    );
    const Features1 = props => (
      <div className="main_logo">
      <div><img src="img/main_logo.png" /></div> 
    </div>
    );

    const Features2 = () => (
      <Block layout="fourColumn">
        {[
          {
            image: `${baseUrl}img/Index3.png`,
            
          },
          {
            image: `${baseUrl}img/Index4.png`,
            
          },
          {
            image: `${baseUrl}img/Index1.png`,
            
          },
          {
            image: `${baseUrl}img/Index2.png`,
            
          },
        ]}
      </Block>
    )
    return (
      
      <SplashContainer>
        <div className="inner">
        <Features1 />
          <ProjectTitle siteConfig={siteConfig} />
          <PromoSection>
            <Button href={docUrl('doc3.html')}>Install</Button>
            <Button href={docUrl('doc2.html')}>Use</Button>
            <Button href={docUrl('doc3.html')}>Configure</Button>
          </PromoSection>
          <Features2 />
        </div>
      </SplashContainer>
    );
  }
}

class Index extends React.Component {
  render() {
    const {config: siteConfig, language = ''} = this.props;
    const {baseUrl} = siteConfig;

    const Block = props => (
      <Container
        padding={['bottom', 'top']}
        id={props.id}
        background={props.background}>
        <GridBlock
          align="center"
          contents={props.children}
          layout={props.layout}
        />
      </Container>
    );
    const Features1 = () => (
      <Block layout="twoColumn">
        {[
          {
            image: `${baseUrl}img/Index1.png`,
            imageAlign: 'left',
          },
          {
            image: `${baseUrl}img/Index2.png`,
            imageAlign: 'right',
          },
        ]}
      </Block>
    );
    const Features2 = () => (
      <Block layout="twoColumn">
        {[
          {
            image: `${baseUrl}img/Index3.png`,
            imageAlign: 'left',
          },
          {
            image: `${baseUrl}img/Index4.png`,
            imageAlign: 'right',
          },
        ]}
      </Block>
    );
    return (
      <div>
        <HomeSplash siteConfig={siteConfig} language={language} />
        <div className="mainContainer">
        </div>
      </div>
    );
  }
}

module.exports = Index;
