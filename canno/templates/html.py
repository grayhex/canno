import html as html_lib


def html(body):
    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Canno Quest</title><link rel='stylesheet' href='/static.css'></head>"
        "<body><div class='app-shell'>"
        "<header class='top-nav'>"
        "<nav class='top-nav-main' aria-label='Основное меню'>"
        "<button id='nav-back' class='top-nav-btn' type='button'><span class='nav-ico' aria-hidden='true'>←</span>Назад</button>"
        "<a id='nav-home' class='top-nav-btn top-nav-link' href='/'><span class='nav-ico' aria-hidden='true'>⌂</span>Домой</a>"
        "<a class='top-nav-btn top-nav-link' href='/admin/login'><span class='nav-ico' aria-hidden='true'>🛡</span>Админ</a>"
        "<a class='top-nav-btn top-nav-link' href='/editor/login'><span class='nav-ico' aria-hidden='true'>✎</span>Редактор</a>"
        "</nav>"
        "<button id='nav-menu-toggle' class='top-nav-btn top-nav-menu-toggle' type='button' aria-expanded='false' aria-controls='nav-mobile-panel'>☰ Меню</button>"
        "<div id='nav-mobile-panel' class='top-nav-mobile-panel' aria-hidden='true'>"
        "<button id='nav-mobile-back' class='top-nav-btn' type='button'><span class='nav-ico' aria-hidden='true'>←</span>Назад</button>"
        "<a class='top-nav-btn top-nav-link' href='/'><span class='nav-ico' aria-hidden='true'>⌂</span>Домой</a>"
        "<a class='top-nav-btn top-nav-link' href='/admin/login'><span class='nav-ico' aria-hidden='true'>🛡</span>Админ</a>"
        "<a class='top-nav-btn top-nav-link' href='/editor/login'><span class='nav-ico' aria-hidden='true'>✎</span>Редактор</a>"
        "</div>"
        "</header>"
        "<div class='bg-noise'></div><div class='bg-grid'></div>"
        "<div class='ambient'></div><div class='ambient-2'></div><div class='ambient-3'></div><div class='ambient-4'></div>"
        f"{body}</div>"
        "<script>(function(){"
        "const isHome=window.location.pathname==='/'||window.location.pathname==='';"
        "const backBtn=document.getElementById('nav-back');const homeBtn=document.getElementById('nav-home');"
        "if(isHome){backBtn.disabled=true;homeBtn.classList.add('disabled');homeBtn.setAttribute('aria-disabled','true');homeBtn.addEventListener('click',(e)=>e.preventDefault());}"
        "backBtn.addEventListener('click',()=>{if(!isHome&&window.history.length>1){window.history.back();}});"
        "const menuToggle=document.getElementById('nav-menu-toggle');const menuPanel=document.getElementById('nav-mobile-panel');const mobileBack=document.getElementById('nav-mobile-back');if(menuToggle&&menuPanel){menuToggle.addEventListener('click',()=>{const expanded=menuToggle.getAttribute('aria-expanded')==='true';menuToggle.setAttribute('aria-expanded',String(!expanded));menuPanel.setAttribute('aria-hidden',String(expanded));menuPanel.classList.toggle('open',!expanded);menuToggle.textContent=!expanded?'✕ Закрыть':'☰ Меню';});if(mobileBack){mobileBack.addEventListener('click',()=>{if(!isHome&&window.history.length>1){window.history.back();}});}}const cards=document.querySelectorAll('.card');"
        "cards.forEach((card)=>{card.addEventListener('mousemove',(e)=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%');});});"
        "const hero=document.querySelector('.home-card');if(hero&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches){window.addEventListener('scroll',()=>{const y=Math.min(window.scrollY,500);hero.style.opacity=String(1-y/500);hero.style.transform='translateY('+(y*0.2)+'px) scale('+(1-y/10000)+')';},{passive:true});}"
        "})();</script></body></html>"
    )


def error_page(code, title, message):
    return html(f"<main class='card'><h1>{code}: {html_lib.escape(title)}</h1><p>{html_lib.escape(message)}</p></main>")
