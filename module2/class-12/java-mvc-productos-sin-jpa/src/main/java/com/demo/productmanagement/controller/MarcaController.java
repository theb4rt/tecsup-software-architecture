package com.demo.productmanagement.controller;

import com.demo.productmanagement.model.Marca;
import com.demo.productmanagement.service.MarcaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
@RequestMapping("/marcas")
public class MarcaController {

    private final MarcaService marcaService;

    @Autowired
    public MarcaController(MarcaService marcaService) {
        this.marcaService = marcaService;
    }

    // List all marcas
    @GetMapping
    public String listMarcas(Model model) {
        model.addAttribute("marcas", marcaService.getAllMarcas());
        return "marcas/list";
    }

    // Show form to create a new marca
    @GetMapping("/new")
    public String showNewMarcaForm(Model model) {
        model.addAttribute("marca", new Marca());
        return "marcas/form";
    }

    // Save a new marca
    @PostMapping
    public String saveMarca(@ModelAttribute Marca marca, RedirectAttributes redirectAttributes) {
        marcaService.saveMarca(marca);
        redirectAttributes.addFlashAttribute("message", "Marca guardada con éxito");
        return "redirect:/marcas";
    }

    // Show form to edit a marca
    @GetMapping("/edit/{id}")
    public String showEditMarcaForm(@PathVariable Long id, Model model, RedirectAttributes redirectAttributes) {
        Optional<Marca> optionalMarca = marcaService.getMarcaById(id);

        if (optionalMarca.isPresent()) {
            model.addAttribute("marca", optionalMarca.get());
            return "marcas/form";
        } else {
            redirectAttributes.addFlashAttribute("error", "Marca no encontrada");
            return "redirect:/marcas";
        }
    }

    // Update a marca
    @PostMapping("/update")
    public String updateMarca(@ModelAttribute Marca marca, RedirectAttributes redirectAttributes) {
        boolean updated = marcaService.updateMarca(marca);

        if (updated) {
            redirectAttributes.addFlashAttribute("message", "Marca actualizada con éxito");
        } else {
            redirectAttributes.addFlashAttribute("error", "Error al actualizar la marca");
        }

        return "redirect:/marcas";
    }

    // View a marca
    @GetMapping("/view/{id}")
    public String viewMarca(@PathVariable Long id, Model model, RedirectAttributes redirectAttributes) {
        Optional<Marca> optionalMarca = marcaService.getMarcaById(id);

        if (optionalMarca.isPresent()) {
            model.addAttribute("marca", optionalMarca.get());
            return "marcas/view";
        } else {
            redirectAttributes.addFlashAttribute("error", "Marca no encontrada");
            return "redirect:/marcas";
        }
    }

    // Delete a marca
    @GetMapping("/delete/{id}")
    public String deleteMarca(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        boolean deleted = marcaService.deleteMarca(id);

        if (deleted) {
            redirectAttributes.addFlashAttribute("message", "Marca eliminada con éxito");
        } else {
            redirectAttributes.addFlashAttribute("error", "Error al eliminar la marca");
        }

        return "redirect:/marcas";
    }
}
