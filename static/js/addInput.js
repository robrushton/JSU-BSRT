
var counter = 2;
function addInput(divName){
    var newdiv = document.createElement('div');
    newdiv.innerHTML = "<input type='datetime-local' name='start-" + counter + "'/> <input type='datetime-local' name='end-" + counter + "' /> <input type='number' name='openings-" + counter + "' placeholder='Openings' /><br>";
    document.getElementById(divName).appendChild(newdiv);
    counter++;
}